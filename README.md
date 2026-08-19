# gil-polinrider-guard

Detection and recovery tooling for **PolinRider**, a supply-chain malware
campaign that hides payloads as invisible-Unicode blobs, disguised binary
assets (e.g. a `.js` payload named like a font file), auto-running VS Code
tasks, and backdated git commits.

Six scanners + an aggregator + a history-surgery recovery tool (CLI, batch,
and browser) — built around one idea: **file extension is a trust model,
not a security model.**

## Quick start

**Web UI** — paste a git URL, watch it clone/scan, read the report in your
browser:

```bash
pip install -e ".[web]"
polinrider-guard-web              # open http://127.0.0.1:8765
```

> **Windows:** if `polinrider-guard-web` isn't found, run
> `python -m polinrider_guard.webapp` instead.

**CLI** — scan a repo already on disk:

```bash
pip install -e .
polinrider-guard /path/to/cloned/repo
```

```bash
polinrider-guard /path/to/cloned/repo --json   # structured output
```

Exit code is `0` if nothing was found, `1` if something was. Try it on the
fixtures shipped in this repo:

```bash
polinrider-guard examples/clean-project --no-git        # -> No findings, exit 0
polinrider-guard examples/vulnerable-samples --no-git    # -> 3 findings, exit 1
```

**Docker** — no local Python needed:

```bash
docker compose up web             # open http://localhost:8765
```

## The six scanners

| Scanner | Detects |
|---|---|
| Extension masquerade | A file's magic bytes don't match its declared extension |
| Risky VS Code tasks | `.vscode/tasks.json` set to auto-run on folder open |
| Known IOC strings | Literal C2 domains / loader markers / decode-and-eval patterns |
| Hidden payload padding | A payload pushed off-screen behind 80+ spaces |
| Clock-tamper tooling | A script that spoofs the system clock to forge a commit date |
| Commit camouflage | A mass-touch reformat commit that sneaks in a new script |

## If a scan finds something

Found a backdated/malicious commit with legitimate work on top of it? Use
the Recovery panel in the Web UI, or:

```bash
git clone --mirror <url> repo.git
python scripts/surgical_clean.py repo.git          # dry run
python scripts/surgical_clean.py repo.git --apply  # rewrite
```

## More

Everything else — the allowlist format, Recovery panel details, GitHub
org/batch scanning, Docker options, workstation hardening, CI setup, YARA
rules, and project layout — is in **[docs/DETAILS.md](docs/DETAILS.md)**.
