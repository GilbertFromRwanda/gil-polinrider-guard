# Safety note

Everything in this directory reproduces the *structural pattern* of the
PolinRider campaign so that `polinrider-guard` (and its component scanners)
can be tested against real positive cases. None of it is functional malware,
and none of it is a byte-identical copy of any real published sample:

- `app.js` contains inert invisible Unicode characters (zero-width space,
  a variation selector, a private-use-area character) sitting in a comment
  and a string literal. They do not change what the function does.
- `lib/analytics.js` contains an unused string constant with a known
  BeaverTail C2 domain fragment. It is never read or called.
- `assets/img/brand-mark.png` is plain JavaScript with a `.png` name,
  demonstrating the binary-extension masquerade vector generically (the
  real campaign has used font files specifically; this fixture deliberately
  uses a different asset type and a different filename so it isn't a
  literal copy of any published IOC). It only prints a line to the console —
  no `eval`, no network access, no credential or filesystem access, no
  blockchain C2.
- `.vscode/tasks.json` reproduces the *structure* the real TasksJacker
  technique relies on (`runOn: folderOpen`, `hide: true`, suppressed
  terminal presentation, a shell command invoking an interpreter against a
  binary-extension path) with different wording/label/paths than the
  published example, pointed at the harmless file above.

### Why this is deliberately reworded, not copy-pasted

An earlier draft of this fixture used the campaign's published example
verbatim (same task label, same command string, same `fa-solid-400.woff2` /
`public/fonts/` path). Windows Defender correctly detected and quarantined
that file as `Trojan:NPM/PolinRider.SB` — it matched a real signature,
because it *was* a byte-for-byte copy of real malware IOC text. This
project does not attempt to evade that kind of detection: instead, this
fixture is intentionally paraphrased so it exercises the same *detection
logic* (structural checks: task auto-run trigger + stealth presentation +
interpreter-vs-binary-extension mismatch) without shipping a literal copy
of found-in-the-wild malicious content. If your antivirus still flags
anything in this directory, treat that as it doing its job -- delete the
flagged file, the test suite will regenerate it, and consider filing that
detail as feedback in this project's issue tracker.

If you open this folder in VS Code with workspace trust / automatic tasks
enabled, the task will run the harmless placeholder script and print a
message to a background terminal. It will not do anything beyond that.

This fixture exists to make `examples/vulnerable-samples` exit non-zero
(findings present) so CI and local test runs have a reliable positive
control, mirroring `examples/clean-project`, which should always exit 0.
