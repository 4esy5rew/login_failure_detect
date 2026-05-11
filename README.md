# hydra_tool

`hydra_tool.py` analyzes a login page, detects the most likely failure string,
and can optionally run a `hydra` standard-credential test against the detected form.

## What It Does

- Fetches a target login URL
- Detects login form fields (username, password, and relevant extra fields)
- Detects a likely login failure string using multiple heuristics
- Optionally runs `hydra` with detected parameters (`--test`)

## Requirements

- Python 3.8+
- `hydra` installed and available in `PATH`
- Python dependencies from `requirements.txt`

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

Show help:

```bash
python hydra_tool.py -h
```

Basic detection only (default mode):

```bash
python hydra_tool.py https://example.com/login
python hydra_tool.py example.com/login
```

Run detection + hydra credential test:

```bash
python hydra_tool.py --test https://example.com/login
```

Verbose mode (extra diagnostics for failure detection):

```bash
python hydra_tool.py -v https://example.com/login
python hydra_tool.py --test -v https://example.com/login
```

Custom wordlists (used only with `--test`):

```bash
python hydra_tool.py --test --userlist wordlists/usernames.txt --passlist wordlists/passwords.txt https://example.com/login
```

## CLI Options

- `url` (positional): Target URL
- `--test`: Run `hydra` using detected form and failure string
- `--userlist`: Username wordlist path (only for `--test`)
- `--passlist`: Password wordlist path (only for `--test`)
- `-v`, `--verbose`: Show additional detection details and debug-oriented output

## Output Modes

- Default: failure detection string only
- `--test`: hydra command + found credentials
- `-v`: adds detection details and detected field listing

## Notes

- If the URL has no scheme, `http://` is added automatically.
- Failure-string detection uses multiple strategies (status/redirect/container/keyword diff/snippet fallback).
- Included wordlists are intentionally small and meant for quick authorized checks.

## Legal / Authorization

Use this tool only on systems you own or have explicit permission to test.
Unauthorized credential testing is illegal.
