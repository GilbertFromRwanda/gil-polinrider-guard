/*
 * YARA rules for the PolinRider (Glassworm / ForceMemo / BeaverTail) campaign.
 *
 * Design principle (see Part 4 of the writeup this project is based on):
 * payload-detection rules here carry NO filename/extension restriction.
 * Limiting a rule to `*.js` is exactly the blind spot the font-file vector
 * exploited -- Node.js runs a file based on its bytes, not its name, so
 * these rules scan file content regardless of what it's called. Extension
 * mismatch gets its own explicit rule (PolinRider_Binary_Extension_Masquerade)
 * that requires the `filename` external variable.
 *
 * Usage:
 *   yara rules/polinrider.yar /path/to/file
 *   yara -r rules/polinrider.yar /path/to/project
 *
 *   # the masquerade rule needs the external "filename" variable so it can
 *   # compare a file's actual content against what its name claims to be:
 *   yara -d filename=path/to/file.woff2 rules/polinrider.yar path/to/file.woff2
 *
 * These are complementary to, not a replacement for, the Python scanners in
 * polinrider_guard/ -- YARA is convenient for CI, pre-commit hooks, and SIEM
 * / file-integrity-monitoring integration; the Python scanners give richer,
 * structured output (line/column, unicode category names, severity).
 */

rule PolinRider_Glassworm_Loader_Marker
{
    meta:
        description = "Glassworm loader initialization marker"
        campaign = "PolinRider"
        severity = "critical"
        reference = "Operation PolinRider writeup, Part 1.2"

    strings:
        $marker = /global\[['"]_V['"]\]\s*=\s*['"]8-/

    condition:
        $marker
}

rule PolinRider_BeaverTail_Blockchain_C2
{
    meta:
        description = "BeaverTail second-stage blockchain C2 endpoint"
        campaign = "PolinRider"
        severity = "critical"
        reference = "Operation PolinRider writeup, Background section"

    strings:
        $trongrid = "trongrid.io" nocase
        $aptoslabs = "aptoslabs.com" nocase
        $bsc_dataseed = "bsc-dataseed" nocase
        $bscscan = "bscscan.com" nocase

    condition:
        any of them
}

rule PolinRider_Eval_Buffer_Decode
{
    meta:
        description = "eval(Buffer.from(...)) decode-and-execute pattern used by BeaverTail payload decryption"
        campaign = "PolinRider"
        severity = "high"

    strings:
        $pattern = /eval\(\s*Buffer\.from\(/

    condition:
        $pattern
}

rule PolinRider_Glassworm_Invisible_Unicode
{
    meta:
        description = "UTF-8 bytes for zero-width / variation-selector code points used to hide the Glassworm payload"
        campaign = "PolinRider"
        severity = "high"
        reference = "Operation PolinRider writeup, Part 1.3"

    strings:
        // U+200B ZERO WIDTH SPACE
        $zwsp = { E2 80 8B }
        // U+200C/U+200D ZWNJ/ZWJ
        $zwnj_zwj = { E2 80 8C }
        $zwj = { E2 80 8D }
        // U+FE00-U+FE0F variation selectors (UTF-8: EF B8 80-8F)
        $vs = /\xEF\xB8[\x80-\x8F]/
        // U+E0100-U+E01EF variation selector supplement (UTF-8: F3 A0 84 80 - F3 A0 87 AF)
        $vs_supp = { F3 A0 (84|85|86|87) }

    condition:
        // A single isolated hit can be legitimate (e.g. real bidi text in a
        // comment or string); Glassworm strings together several DIFFERENT
        // invisible-character categories to encode bytecode, so requiring
        // more than one category matched is the signal, not raw count.
        2 of them
}

rule PolinRider_TasksJacker_FolderOpen_Autorun
{
    meta:
        description = "VS Code tasks.json configured to auto-run on folder open with output hidden from the user"
        campaign = "PolinRider"
        severity = "critical"
        reference = "Operation PolinRider writeup, Part 4"

    strings:
        $run_on_folder_open = "\"runOn\"" nocase
        $folder_open_value = "\"folderOpen\""
        $hide_true = "\"hide\"" nocase
        $reveal_never = "\"reveal\": \"never\"" nocase

    condition:
        filename matches /tasks\.json$/i
        and $run_on_folder_open and $folder_open_value
        and ($hide_true or $reveal_never)
}

rule PolinRider_Binary_Extension_Masquerade
{
    meta:
        description = "File declares a binary media/font extension but its content is JavaScript (font-file masquerade vector)"
        campaign = "PolinRider"
        severity = "critical"
        reference = "Operation PolinRider writeup, Part 4"

    strings:
        $js1 = "function" fullword
        $js2 = "require("
        $js3 = "module.exports"
        $js4 = "=>"
        $magic_woff2 = { 77 4F 46 32 } // "wOF2"
        $magic_woff  = { 77 4F 46 46 } // "wOFF"
        $magic_png   = { 89 50 4E 47 0D 0A 1A 0A }
        $magic_ttf1  = { 00 01 00 00 }
        $magic_otf   = { 4F 54 54 4F } // "OTTO"

    condition:
        filename matches /\.(woff2?|ttf|otf|eot|png|jpe?g|gif|ico|wasm)$/i
        and 2 of ($js*)
        and not (
            $magic_woff2 at 0 or $magic_woff at 0 or $magic_png at 0 or
            $magic_ttf1 at 0 or $magic_otf at 0
        )
}
