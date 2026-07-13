---
name: probeagent-filesystem-wedge
description: >
  Recover this repo's working copy when files read as empty/corrupt or reads hang.
  LOAD THIS the moment you see any of: a file that `ls`/`stat` shows as N bytes but
  reads as empty; md5 == d41d8cd98f00b204e9800998ecf8427e on a non-empty file;
  "short read: Undefined error: 0" from git/grep; ImportError "No module named
  'probeagent'" even though tests pass; pytest failing on a symbol that exists in
  source; a Read/cat/open that hangs forever. This machine's filesystem intermittently
  wedges — inode metadata stays intact while data blocks go empty or unreadable. This
  is the single most destructive trap in this project; a model that doesn't recognize
  it will "fix" phantom bugs for hours.
---

# ProbeAgent filesystem wedge — detect and recover

This repo lives on a filesystem that intermittently **wedges**: a file's inode still
reports its old size (`ls -l`, `stat`, `wc -c` all show N bytes), but the actual data
blocks read as **empty** or **error**, and the fault survives a reboot (it is on-disk,
not just a cache/lock). It has hit working-tree files, the `.venv`, and even `.git`
loose objects in one session. Concurrent reads make it worse.

**When NOT to use:** if files read correctly and tests import fine, you are not wedged —
do not run these recovery steps speculatively. For the normal test/commit/release flow
use [[probeagent-build-test-and-release]].

## Golden rules (obey even when they slow you down)

- Run **one** `pytest` at a time, in the foreground. NEVER background it, run parallel
  pytest, or fan out Explore/agent searches over the repo — concurrent reads trigger the wedge.
- Prefer targeted `Read`/`grep` of known paths over broad recursive scans.
- If a content read hangs, do not retry it in a loop; jump to recovery below.

## Detect it

An "empty-md5" scan MISSES files whose reads *error* instead of returning empty. Detect
by comparing **readable bytes** to the git blob (or a clean clone):

```bash
# per file: readable bytes vs git's stored blob size
f=path/to/file
echo "readable=$(cat "$f" 2>/dev/null | wc -c | tr -d ' ')  blob=$(git cat-file -s "HEAD:$f" 2>/dev/null)"
# readable=0 while blob>0  → CORRUPT
```

Sweep all tracked files against a clean clone (see recovery step 2 for the clone):

```bash
while IFS= read -r f; do
  [ -f "$CLEAN/$f" ] || continue
  cb=$(wc -c < "$CLEAN/$f" | tr -d ' '); [ "$cb" -gt 0 ] || continue
  wb=$(cat "$f" 2>/dev/null | wc -c | tr -d ' ')
  [ "$wb" = 0 ] && echo "CORRUPT $f (clean=$cb wt=0)"
done < <(git ls-files)
```

## Recover

### 1. Tracked working-tree file, git object store intact
Restore from git via a fresh inode (atomic rename never touches the bad inode):
```bash
f=path/to/file; git show "HEAD:$f" > "$f.restore.$$" && mv -f "$f.restore.$$" "$f"
# verify it took (empty-file md5 = d41d8cd9...427e means it did NOT):
md5 -q "$f"
```

### 2. git object store ALSO corrupt (git show yields empty; `git cat-file -s HEAD:$f` blank but `git rev-parse HEAD:$f` resolves)
Recover from origin via a shallow clone in the scratchpad, then repair the local object:
```bash
CLEAN=<scratchpad>/probeagent-clean
git clone --depth 1 --branch main "$(git remote get-url origin)" "$CLEAN"
rm -f "$f"; cp "$CLEAN/$f" "$f"                 # rm drops the wedged inode; cp writes a fresh one
# repair the corrupt loose object so future git ops don't choke:
blob=$(git rev-parse "HEAD:$f")
[ "$(git hash-object "$f")" = "$blob" ] && { chmod u+w ".git/objects/${blob:0:2}/${blob:2}"; rm -f ".git/objects/${blob:0:2}/${blob:2}"; git hash-object -w "$f" >/dev/null; }
git fsck --full        # expect clean
```

### 3. `.venv` corrupt (e.g. empty `pygments/util.py`, broken `pip`)
Do NOT repair individual packages. Rebuild:
```bash
mv .venv .venv.corrupt.$$          # atomic; rm later
uv venv --python 3.12 .venv
uv pip install -e ".[dev]"
```

### 4. Editable install `.pth` wedged (CLI/import fails but pytest works)
Symptom: `.venv/bin/probeagent` or `python -c "import probeagent"` fails with
`ModuleNotFoundError: No module named 'probeagent'`, while `pytest` still imports fine.
The `__editable__.probeagent_ai-*.pth` in site-packages reads empty. Reinstalling
editable fixes it temporarily but it degrades again. **Reliable workaround: prefix every
CLI/python invocation with `PYTHONPATH=src`.**
```bash
PYTHONPATH=src .venv/bin/probeagent --version
PYTHONPATH=src .venv/bin/python -m pytest -q
```

### 5. After restoring test/source files: clear stale bytecode
Stale `__pycache__` masks the corruption (a test can pass against a cached `.pyc` of a
now-empty file). Clear it, excluding `.venv`:
```bash
find . -path ./.venv -prune -o -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null
# then run pytest with -p no:cacheprovider once, foreground
```

## Provenance & maintenance
- Written 2026-07-12 from a live recovery: 5 tracked files, the whole `.venv`, and one
  `.git` loose object were wedged post-reboot; recovered via the steps above.
- Empty-file md5 is constant: `d41d8cd98f00b204e9800998ecf8427e`.
- Re-verify the empty-read scan still works: `git ls-files | head -1` then run the per-file
  check above against it (readable bytes should equal `git cat-file -s`).
- Related: [[probeagent-build-test-and-release]] (why `PYTHONPATH=src` and single-run pytest).
