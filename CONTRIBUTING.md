# Contributing

Got sent a repo that turned out to be malicious, or found a trick the scanner
misses? Add it. Every case and rule makes the next audit better.

Ways to contribute:

- **A case study** of a malicious repo you've seen
- **A detection rule** for a trick the scanner doesn't catch yet
- **A false-positive fix** if the scanner flags something normal in a real project
- **Improvements to the skill instructions** (`SKILL.md`)

## Safety rules (read first)

This repo must never become a way to spread malware.

- **No live payloads.** Don't commit malware, encrypted blobs, carrier
  files, obfuscated payload code, or anything that runs. Short excerpts
  (a few lines) that show the technique are fine.
- **Keep indicators inert.** Put URLs, IPs and domains inside backticks or
  code blocks so they aren't clickable, or defang them (`hxxps://evil[.]example`).
- **Test fixtures must be inert.** They should only *look* like the trap: for
  example, a `.git/config` with an `fsmonitor` line, or a hook file full of
  string constants. Nothing in them may execute, reach the network, or write
  outside a temp folder.
- **No personal data.** Leave out names, emails, usernames, client names,
  and paths like `/Users/<you>/`.
- **Don't run the malicious repo** to write it up. Analyse it statically, the
  way the skill does.

## Adding a case study

Create `cases/NN-short-name.md` (next number), using this outline:

```markdown
# Case NN: `<repo name>`. <one line: what triggers it>

| | |
|---|---|
| **Delivered as** | e.g. take-home zip, GitHub link from a "client", npm package |
| **Triggered by** | e.g. opening the folder, `npm install`, `npm run dev`, running tests |
| **Needed `npm install`?** | Yes / No |
| **Impact** | What it does when it fires |
| **Family** | Known campaign or malware family, if you know it |

## What it looked like
## The trap
## What happens when it fires
## Indicators
## How to clean up
## How the skill catches it   (scanner output, or what's missing - then add a rule)
```

Then add a row to the cases table in `README.md`, and a short summary to
`skill/repo-safety-check/references/case-studies.md`.

## Adding or changing a scanner rule

The scanner is `skill/repo-safety-check/scripts/scan_repo.py`. Keep it:

- **Read-only.** It must never execute, import, or extract anything from the
  target.
- **Standard library only.** No pip installs.
- **Quiet on normal projects.** Run it on a couple of your own real repos
  and make sure your rule doesn't add noise.

Where things go:

| You want to catch... | Edit |
|---|---|
| A suspicious line of code | `CODE_RULES` |
| Text aimed at AI tools | `AI_DIRECTED` |
| Git config or hook tricks | `check_git_config` / `check_git_hook` |
| Auto-run on install or open | `check_package_json`, or the `.vscode` / devcontainer checks |
| Hidden data in files | `check_binary` / `check_svg_html` |
| Staging hosts | `SUSPICIOUS_HOSTS` |

Every new rule needs a test in `tests/test_scanner.py`:

- an **inert fixture** that triggers the rule;
- a **normal example** that should stay quiet (add phrases to `shouldnt`,
  or content to the clean project).

## Before opening a PR

```bash
python3 -I tests/test_scanner.py
```

All tests should pass. Also run the scanner on at least one normal project
you trust. Then open a PR that briefly explains what the trap does and how your
change catches it.

Not ready to write it up yourself? Open an issue describing what you saw:
the trigger, the files involved, and any indicators. Someone can turn it into a
case.
