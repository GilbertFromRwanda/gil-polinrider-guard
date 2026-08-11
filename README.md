# gil-polinrider-guard

Detection and recovery tooling for the PolinRider supply-chain campaign: a
DPRK-linked attack that injects invisible-Unicode payloads into source files
(Glassworm), falsifies git history to hide the injection commit (ForceMemo),
runs a blockchain-backed second stage (BeaverTail), and — the most recent
confirmed variant — disguises the payload as a binary asset like a font file
so extension-based scanners never look at it (the "font-file vector").

This project gives you five independent scanners, an aggregator, a
history-surgery tool, a batch recovery script, YARA rules, git hooks, and a
CI workflow, all built around one idea: **file extension is a trust model,
not a security model.** None of the detectors here gate on filename except
where the mismatch between name and content *is* the thing being detected.

## Install

```bash
pip install -e .
# or, for running the test suite too:
pip install -e ".[dev]"
```

This installs five console commands: `polinrider-scan-unicode`,
`polinrider-scan-masquerade`, `polinrider-scan-vscode`,
`polinrider-scan-git-dates`, `polinrider-scan-ioc`, and the aggregator,
`polinrider-guard`.

## Quick start: scan before you open a project

The highest-leverage thing you can do is scan a repository **before**
opening it in an IDE — this is what stops the auto-executing task from ever
running in the first place.

```bash
polinrider-guard /path/to/cloned/repo
```

```bash
polinrider-guard /path/to/cloned/repo --json   # structured output
polinrider-guard /path/to/cloned/repo --no-git # skip git history checks (e.g. not a repo yet)
```

Exit code is `0` if nothing was found, `1` if something was.

Try it against the fixtures shipped in this repo:

```bash
polinrider-guard examples/clean-project --no-git        # -> No findings, exit 0
polinrider-guard examples/vulnerable-samples --no-git    # -> 3-4 findings, exit 1
```

See [examples/vulnerable-samples/SAFETY.md](examples/vulnerable-samples/SAFETY.md)
for what that fixture contains and why it's safe.

## The five scanners

| Scanner | Detects | Command |
|---|---|---|
| Invisible Unicode | Glassworm: zero-width/variation-selector/private-use-area code points hiding a payload | `polinrider-scan-unicode PATH` |
| Extension masquerade | Font-file vector: a file's magic bytes don't match its declared extension (e.g. JS content named `.woff2`) | `polinrider-scan-masquerade PATH` |
| Risky VS Code tasks | TasksJacker: `.vscode/tasks.json` configured to auto-run on folder open with output hidden | `polinrider-scan-vscode PATH` |
| Git date backdating | ForceMemo: commits where the author/committer date gap implies history was rewritten and backdated | `polinrider-scan-git-dates PATH` |
| Known IOC strings | Literal BeaverTail C2 domains / Glassworm loader marker / decode-and-eval pattern sitting in plain (non-hidden) source | `polinrider-scan-ioc PATH` |

Each one also works standalone with `--json` for scripting, and each is a
plain Python module under `polinrider_guard/` if you want to call it as a
library instead of a CLI.

## Recovering an already-compromised repository

If `polinrider-guard` finds a backdated/malicious commit that has legitimate
work on top of it, don't `git revert` (conflicts with everything after it)
and don't delete the file from history (destroys the legitimate work too).
Use the surgical cleaner, which strips only the offending lines from every
historical blob:

```bash
git clone --mirror <url> repo.git      # never rewrite your only copy
python scripts/surgical_clean.py repo.git                # dry run (default)
python scripts/surgical_clean.py repo.git --apply         # actually rewrite
# then, only after you've inspected the result yourself:
cd repo.git && git push --force --all && git push --force --tags
```

Requires `pip install git-filter-repo`. Full details, including why this
approach is used instead of `git filter-repo --invert-paths`, are in
[docs/ENTERPRISE_RECOVERY.md](docs/ENTERPRISE_RECOVERY.md).

### Cleaning many repositories at once

```bash
scripts/batch-clean.sh --repo-list repos.txt --workdir ./recovery
```

Clones each repo, runs `polinrider-guard` against a working copy (for the
audit trail), mirror-clones it, runs the surgical cleaner, and writes a
JSON-lines audit log to `./recovery/recovery-audit.jsonl`. **Never pushes on
its own** — add `--push --i-know-what-im-doing` only once you've reviewed
the result and coordinated with collaborators (their clones will need to be
re-cloned afterward).

## Hardening a workstation

```bash
scripts/install-hooks.sh
```

Installs `pre-commit` (blocks a commit if the working tree has findings)
and `post-merge` (warns loudly after a merge/pull) as **global** git hooks
via `core.hooksPath`, so they run for every repo on the machine, not just
one. Bypass a single commit with `POLINRIDER_GUARD_SKIP=1 git commit ...`
or `git commit --no-verify`.

Also recommended: open unfamiliar repositories inside a
[Dev Container](https://containers.dev/) rather than your host environment,
disable VS Code's automatic-task execution
(`"task.allowAutomaticTasks": "off"` in user settings), and use
`npm install --ignore-scripts` on first install of an unfamiliar project.

## CI integration

`.github/workflows/polinrider-guard.yml` runs the test suite, self-scans
this project's own source (must be clean), and runs the negative-control
check (`examples/clean-project` must stay clean, `examples/vulnerable-samples`
must keep triggering findings — so a detection regression fails CI instead
of going unnoticed). Enforce it with branch protection so a compromised
contributor can't just edit the workflow file away; see
[docs/GITHUB_PROTECTION.md](docs/GITHUB_PROTECTION.md).

## YARA rules

`rules/polinrider.yar` has the same detections as the Python scanners, for
environments that already run YARA (SIEM, file-integrity monitoring,
pre-commit via `yara` CLI). Deliberately **not** filtered by file extension
for the payload rules — extension filtering is exactly what let the
font-file vector go undetected in the first place. The one rule that does
care about extension (`PolinRider_Binary_Extension_Masquerade`) uses it as
the thing being checked *against* the content, not as a gate on which files
get scanned.

```bash
yara -d filename=path/to/file rules/polinrider.yar path/to/file
```

## Project layout

```
polinrider_guard/       the five scanners + guard.py aggregator + shared IOC list
scripts/
  surgical_clean.py     history-surgery tool (dry-run by default)
  batch-clean.sh         multi-repo recovery orchestrator
  install-hooks.sh       installs global git hooks
hooks/                   pre-commit / post-merge hook scripts
rules/polinrider.yar     YARA rules
examples/
  clean-project/         negative control -- must always report 0 findings
  vulnerable-samples/     positive control -- reworded, inert fixtures (see SAFETY.md)
tests/                   pytest suite exercising every scanner + surgical clean
docs/
  ENTERPRISE_RECOVERY.md  full recovery walkthrough
  GITHUB_PROTECTION.md    branch protection settings for the CI workflow
```

## What this does not cover

This project is about detecting and recovering from the file/repo/IDE-level
IOCs of this specific campaign. It does not cover npm registry-level package
compromise (check your `node_modules` against published IOC lists
separately), notifying downstream forks of a public repository, or incident
reporting/legal obligations. Treat a positive finding as the start of an
investigation, not the end of one.
