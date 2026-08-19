# Enterprise recovery: cleaning history without losing legitimate work

This walks through recovering a repository where a PolinRider-style
malicious commit has legitimate commits on top of it — the case where the
naive fixes (`git revert`, `git filter-repo --invert-paths`) both fail you.

## Why the naive approaches don't work

**`git revert`** adds a new commit undoing the malicious one's diff. If
nothing has touched the same lines since, this is fine. If legitimate
commits *have* touched those files since (the realistic case — the whole
reason cleanup is hard is that development kept happening on top of the
injection), the revert either conflicts outright or, worse, silently
"succeeds" while leaving a confusing merge that's hard to audit and doesn't
actually restore the pre-injection state in history.

**`git filter-repo --path <file> --invert-paths`** removes a file from
*every* commit in history — including all the legitimate versions of it. If
PolinRider appended a few lines to the end of `src/index.js`, this deletes
months of legitimate changes to `src/index.js` along with the two malicious
lines.

## The surgical approach

The fix operates at the blob level: for every version of every file that
has ever existed in history, strip only the lines matching a known IOC
pattern, and leave everything else byte-for-byte unchanged. `git
filter-repo --blob-callback` does exactly this — it hands you every blob in
the object database and lets you rewrite its content in place.

`scripts/surgical_clean.py` implements this:

1. **Analyze** (default, read-only): walks every blob reachable from every
   ref (`git rev-list --objects --all` + `git cat-file --batch`), checks
   each line against the IOC pattern list in `polinrider_guard/iocs.py`,
   and reports which blobs/lines would be touched. Nothing is modified.

2. **Apply** (`--apply`): generates a small Python snippet that strips
   matching lines from `blob.data`, and hands it to `git filter-repo
   --blob-callback`. This rewrites every commit's tree to point at the
   cleaned blobs. Commits whose *only* change was the injected lines become
   empty and get pruned automatically by `git filter-repo` — which is
   correct: a commit that existed purely to inject the payload should not
   survive the cleanup.

3. **Verify**: re-runs the analysis after the rewrite and fails loudly if
   anything still matches.

## Step by step

```bash
# 1. Make a mirror clone. Never run this against your only working copy --
#    git filter-repo refuses to run on a non-fresh clone anyway, but a
#    mirror clone is also just the right way to stage a history rewrite.
git clone --mirror https://github.com/org/repo.git repo.git

# 2. Confirm what's there before touching anything.
python scripts/surgical_clean.py repo.git
#    (equivalent to the default; there's no separate --analyze flag needed)

# 3. Rewrite.
python scripts/surgical_clean.py repo.git --apply

# 4. Inspect the result yourself. At minimum:
cd repo.git
git log --oneline --all              # malicious-only commits should be gone
git log --all -p | grep -i trongrid  # should find nothing
cd ..

# 5. Only once you're satisfied, push. This is not automated -- do it
#    deliberately, and tell collaborators first.
cd repo.git
git push --force --all
git push --force --tags
```

## After pushing

Every collaborator's existing local clone now has diverged, unrecoverable
history relative to the rewritten remote. There is no `git pull` fix for
this — they need to **re-clone**. Tell them before you push, not after.

If the repository is public, check **Insights → Forks** for forks made
during the compromise window; those still contain the original poisoned
history and won't be affected by your rewrite.

## Extending the IOC list

`polinrider_guard/iocs.py` is the single source of truth for the literal
patterns used by both `polinrider-scan-ioc` and the surgical cleaner. Add a
new `(pattern_bytes, description, severity)` tuple there and both tools
pick it up. For a one-off pattern you don't want to add permanently, pass
`--iocs-file custom-patterns.txt` to `surgical_clean.py` (one regex per
line, `#`-prefixed lines ignored).

## Multi-repository recovery

See [DETAILS.md](DETAILS.md#cleaning-many-repositories-at-once) for
`scripts/batch-clean.sh`, which runs this whole flow (minus the push, unless
you explicitly opt in) across a list of repositories and produces a
JSON-lines audit log.
