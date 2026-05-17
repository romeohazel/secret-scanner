# secret-scanner

A small CLI that recursively scans a directory for leaked secrets — API keys,
tokens, private keys, and generic high-entropy strings assigned to suspiciously
named variables. Everything it prints is redacted.

dont use this git leaks is better

## Install

No dependencies. Just clone and run with Python 3:

```
python scanner.py <directory>
```

Optional flag:

- `--verbose` / `-v` — print each file as it is scanned or skipped

Exit code is `1` if anything is found, `0` if the tree is clean.

## Example

```
$ python scanner.py ./myapp
myapp/.env
  line 3: [Stripe Live Key] sk_l****************************789a

myapp/config.py
  line 12: [AWS Access Key] AKIA****************WXYZ
  line 25: [Generic High-Entropy Secret] aB3d********************wXyZ

3 secrets found across 2 files.
```

## What it detects

- AWS access keys (`AKIA...`)
- GitHub personal access tokens (`ghp_...`, `github_pat_...`)
- Stripe live keys (`sk_live_...`)
- Google API keys (`AIza...`)
- JWT / Supabase-style tokens (`eyJ...eyJ...`)
- PEM private key blocks (`-----BEGIN ... PRIVATE KEY-----`)
- Generic secrets: assignments like `password = "..."` or `api_key: "..."`
  whose value is long enough and high-entropy enough to look real

## Caveats

This is a best-effort scanner, not a guarantee. It will miss obfuscated or
encoded secrets, and the entropy heuristic produces false positives on things
like hashes, UUIDs, or random test fixtures. Treat a clean report as
"nothing obvious," not "definitely safe."
