"""Shared IOC (indicator of compromise) patterns for the PolinRider campaign.

Used by both `scan_ioc.py` (scans plain visible source for these strings)
and `scripts/surgical_clean.py` (strips matching lines from git history), so
there is exactly one list to keep updated as the campaign evolves.

These match on structure -- a blockchain C2 domain, the published XOR-key
marker, an eval-of-decoded-Buffer decode pattern -- rather than any single
literal payload string, since the specific bytes change between variants
while these anchors have stayed stable across the campaign. Each pattern is
(regex_bytes, human description, severity).
"""

DEFAULT_IOC_PATTERNS: list[tuple[bytes, str, str]] = [
    (rb"global\[\s*['\"]_V['\"]\s*\]\s*=\s*['\"]8-", "Glassworm loader marker (global['_V']='8-...')", "critical"),  # polinrider-guard:ignore
    (rb"trongrid\.io", "TRON blockchain C2 endpoint (BeaverTail)", "critical"),  # polinrider-guard:ignore
    (rb"aptoslabs\.com", "Aptos blockchain C2 endpoint (BeaverTail)", "critical"),  # polinrider-guard:ignore
    (rb"bsc-dataseed", "Binance Smart Chain C2 endpoint (BeaverTail)", "critical"),  # polinrider-guard:ignore
    (rb"bscscan\.com", "Binance Smart Chain explorer API used as C2 (BeaverTail)", "high"),  # polinrider-guard:ignore
    (rb"eval\(\s*Buffer\.from\(", "eval(Buffer.from(...)) decode-and-execute pattern", "high"),  # polinrider-guard:ignore
    (rb"global\.i\s*=\s*[\"'][A-Za-z0-9]{1,10}-\d{2,6}[\"']", "PolinRider implant/build ID marker (global.i='<id>')", "critical"),  # polinrider-guard:ignore
    (rb"global\.r\s*=\s*require\s*;", "PolinRider require-to-global stash (global.r=require) evasion pattern", "critical"),  # polinrider-guard:ignore
    (rb"require\(\s*[\"'](?:\\u[0-9A-Fa-f]{4}){3,}[\"']\s*\)", "Unicode-escaped module name passed to require() -- evades literal string matching", "high"),  # polinrider-guard:ignore
    (rb"[\"'](?:\\u[0-9A-Fa-f]{4}){4,}[\"']", "Unicode-escaped string literal (4+ consecutive \\u escapes) -- evades literal string matching", "high"),  # polinrider-guard:ignore
    (rb"detached\s*:\s*(?:true|!0)[^;]{0,150}stdio\s*:\s*[\"']ignore[\"']", "Detached, hidden, stdio-suppressed background process spawn (HiddenSpawn persistence pattern)", "critical"),  # polinrider-guard:ignore
    (rb"\.subarray\(0,\s*4\)[\s\S]{0,80}\.subarray\(4,\s*8\)", "Blockchain-transaction-address decoded as an IP address (EtherHiding C2 resolution)", "critical"),  # polinrider-guard:ignore
]
