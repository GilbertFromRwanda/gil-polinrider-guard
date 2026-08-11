# Protecting the CI workflow

`.github/workflows/polinrider-guard.yml` is only a real control if an
attacker with commit/PR access can't just edit or delete it. If someone
compromises a contributor's credentials (which is exactly what this
campaign's ForceMemo/BeaverTail stages are built to do), the first thing a
capable attacker does is disable the thing that would catch them.

## Minimum recommended settings

In the repository's **Settings → Branches → Branch protection rules**, add
a rule for your default branch (typically `main`) with:

- **Require a pull request before merging** — no direct pushes to the
  protected branch, including by admins if you can tolerate that (see
  "Include administrators" below).
- **Require approvals** — at least 1 reviewer, ideally 2 for anything that
  touches `.github/workflows/`.
- **Require status checks to pass before merging** — select the jobs from
  `polinrider-guard.yml` (`test`, `self-scan`, `negative-control`, and
  `yara-lint` if enabled). This is what actually makes the workflow load-
  bearing: a PR that fails the negative-control check (detection broke) or
  introduces a finding in `self-scan` cannot merge.
- **Require branches to be up to date before merging** — prevents a stale
  PR from merging around a check that would have failed against current
  `main`.
- **Include administrators** — without this, anyone with admin rights
  (including a compromised admin account) can bypass every rule above.
- **Restrict who can push to matching branches** — combined with the PR
  requirement, this is what actually prevents a force-push from an attacker
  who has stolen a token but not repo admin rights.

## Specifically for the workflow file

GitHub does not have a "protect this one file" setting by default, but two
things get you most of the way there:

1. **CODEOWNERS**: add a `.github/CODEOWNERS` entry —
   ```
   /.github/workflows/ @your-org/security-team
   ```
   Combined with "Require review from Code Owners" in the branch protection
   rule, any PR touching the workflow directory requires sign-off from a
   specific team, not just any reviewer.

2. **Required status checks make silent tampering visible**: if the
   protection rule requires the `polinrider-guard.yml` jobs by name, and an
   attacker's PR *removes* those jobs from the workflow file, the required
   check simply never reports — which GitHub treats as a **failing**
   requirement (an unresolved required check blocks merge), not a passing
   one. This is why selecting the specific job names as required checks
   matters more than just "some CI must be green."

## Rotating credentials after a suspected compromise

Branch protection assumes the attacker doesn't already have a valid,
authorized token. If you're here because `polinrider-guard` or the
Part 1 triage steps found something, branch protection is a forward-looking
control, not a remediation for tokens already stolen — revoke those first
(see the main writeup's Part 1.1: revoke PATs, delete SSH keys, audit
Settings → Applications → Authorized OAuth Apps, from a clean machine).

## Verifying the workflow actually blocks what it should

Periodically confirm the required checks still do their job: open a
throwaway PR that reintroduces one line from `examples/vulnerable-samples`
into a scratch file outside `examples/`, and confirm the `self-scan` or
`negative-control` job fails and blocks merge. Revert the throwaway change
before closing the PR.
