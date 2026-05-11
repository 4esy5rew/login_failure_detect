#!/usr/bin/env python3
"""hydra_tool.py

Parses a remote URL containing a login form, extracts username/password field names,
creates a hydra http-post-form command and executes it automatically.

Usage:
    python hydra_tool.py url

Defaults: uses wordlists/usernames.txt and wordlists/passwords.txt (created in this repo).
"""
import argparse
from pathlib import Path
import shlex
import subprocess
import sys
import textwrap
from urllib.parse import urljoin, urlparse, quote

# ANSI color codes for terminal output
class Color:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    GREY = '\033[90m'

try:
    import requests
except Exception:
    print("Requests not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except Exception:
    print("BeautifulSoup4 not installed. Run: pip install -r requirements.txt")
    sys.exit(1)


SCRIPT_DIR = Path(__file__).resolve().parent


def resolve_local_path(path_value):
    path = Path(path_value)
    if path.is_absolute():
        return str(path)
    return str(SCRIPT_DIR / path)


def find_login_form(soup):
    # prefer forms that contain an input type=password
    forms = soup.find_all('form')
    for form in forms:
        if form.find('input', {'type': 'password'}):
            return form
    return forms[0] if forms else None


def detect_fields(form):
    inputs = form.find_all('input')
    username_field = None
    password_field = None
    other_fields = []
    for inp in inputs:
        itype = (inp.get('type') or '').lower()
        name = inp.get('name') or inp.get('id')
        value = inp.get('value') or ''
        if not name:
            continue
        if itype == 'password' and not password_field:
            password_field = name
        elif itype in ('text', 'email') and not username_field:
            username_field = name
        else:
            # include hidden and other inputs
            other_fields.append((name, value))

    # Fallback: if username not found, pick first non-password input
    if not username_field:
        for inp in inputs:
            name = inp.get('name') or inp.get('id')
            if not name:
                continue
            itype = (inp.get('type') or '').lower()
            if itype != 'password':
                username_field = name
                break

    return username_field, password_field, other_fields


def build_post_string(username_field, password_field, other_fields):
    parts = []
    if username_field:
        parts.append(f"{username_field}=^USER^")
    if password_field:
        parts.append(f"{password_field}=^PASS^")
    for name, val in other_fields:
        # URL-encode values to prevent hydra parsing errors with special chars
        encoded_val = quote(val, safe='')
        parts.append(f"{name}={encoded_val}")
    return '&'.join(parts)


def detect_failure_string(session, submit_url, method, username_field, password_field, other_fields, initial_soup, return_details=False):
    import uuid
    bogus_user = 'no_user_' + uuid.uuid4().hex[:6]
    bogus_pass = 'bad_pass_' + uuid.uuid4().hex[:6]
    details = {
        'submit_url': submit_url,
        'method': method.upper(),
        'bogus_user': bogus_user,
        'bogus_pass': bogus_pass,
        'response_url': None,
        'status_code': None,
        'detected_by': None,
        'failure': None,
    }

    def finalize(failure, source):
        if return_details:
            details['detected_by'] = source
            details['failure'] = failure
            return failure, details
        return failure

    data = {}
    if method == 'post':
        data[username_field] = bogus_user
        data[password_field] = bogus_pass
        for n, v in other_fields:
            data[n] = v
        try:
            resp = session.post(submit_url, data=data, timeout=10, allow_redirects=True)
        except Exception:
            return finalize(None, 'request-error')
    else:
        params = {username_field: bogus_user, password_field: bogus_pass}
        for n, v in other_fields:
            params[n] = v
        try:
            resp = session.get(submit_url, params=params, timeout=10, allow_redirects=True)
        except Exception:
            return finalize(None, 'request-error')

    details['response_url'] = resp.url
    details['status_code'] = resp.status_code

    post_soup = BeautifulSoup(resp.text, 'html.parser')

    # Helper function to extract lines
    def lines_from_soup(soup):
        return [l.strip() for l in soup.get_text('\n').splitlines() if l.strip()]

    # 1) If HTTP status indicates authorization issue, return that
    if resp.status_code in (401, 403):
        failure = f"HTTP {resp.status_code} {resp.reason}"
        return finalize(failure, 'http-status')

    # 2) If response redirected to different URL, check for auth-failure indicators
    if resp.url and resp.url != submit_url:
        # Look for patterns like "false=1", "error=1", "auth=0" in query
        query = urlparse(resp.url).query
        if 'false=' in query or 'error=' in query or 'auth=0' in query:
            failure = 'Authentication failed'
            return finalize(failure, 'redirect-query')
        # Other redirects might indicate auth issues too
        # but we'll continue to text-based detection below

    # 3) Look for common error containers by class or id
    selectors = [
        '[class*="error"]', '[class*="err"]', '[class*="alert"]', '[class*="warning"]',
        '[id*="error"]', '[id*="err"]', '[id*="alert"]', '[id*="warning"]',
        '[role="alert"]', '[aria-live]'
    ]
    for sel in selectors:
        found = post_soup.select(sel)
        if found:
            for el in found:
                txt = el.get_text(separator=' ', strip=True)
                if txt and 4 <= len(txt) <= 300:
                    failure = txt[:80]
                    return finalize(failure, f'container:{sel}')

    keywords = ['invalid', 'failed', 'incorrect', 'error', 'denied', 'unauthorized', 'not valid', 'try again', 'authentication failed', 'login failed', 'username or password', 'not match', 'wrong', 'bad', 'ungültig', 'fehlgeschlagen', 'falsch', 'authentifizierung', 'anmeldung fehlgeschlagen', 'falsches passwort']
    
    post_lines = lines_from_soup(post_soup)
    initial_lines = lines_from_soup(initial_soup)

    # Candidate lines that appear after failed login but not on initial page
    diff_lines = [l for l in post_lines if l not in initial_lines and len(l) <= 300]

    # Strategy: prefer very short lines with keywords (likely error messages)
    error_lines = [l for l in diff_lines if any(k in l.lower() for k in keywords)]
    if error_lines:
        # Sort by length ascending, prefer shortest concise error
        error_lines.sort(key=len)
        # Return first line that's not just a single word and under 80 chars
        for line in error_lines:
            if 6 <= len(line) <= 80:
                failure = line[:80]
                return finalize(failure, 'keyword-diff')
        # If all are very short, still use shortest
        if error_lines:
            failure = error_lines[0][:80]
            return finalize(failure, 'keyword-diff')

    # 4) Try title/meta differences
    title_before = (initial_soup.title.string if initial_soup.title and initial_soup.title.string else '').strip()
    title_after = (post_soup.title.string if post_soup.title and post_soup.title.string else '').strip()
    if title_after and title_after != title_before:
        low = title_after.lower()
        if any(k in low for k in keywords):
            failure = title_after[:80]
            return finalize(failure, 'title')

    # 5) Search for text containing keywords, prefer short snippets
    body_text = post_soup.get_text(' ', strip=True)
    for k in keywords:
        # Case-insensitive search
        idx = body_text.lower().find(k)
        if idx >= 0:
            # Find sentence boundaries (., !, ?) near keyword
            start = max(0, idx - 50)
            end = min(len(body_text), idx + len(k) + 100)
            snippet = body_text[start:end].strip()
            
            # Try to find sentence boundaries
            for delim in ['.', '!', '?']:
                last_delim = snippet.rfind(delim)
                if last_delim > len(k) and last_delim < len(snippet) - 1:
                    snippet = snippet[:last_delim + 1].strip()
                    break
            
            if 8 <= len(snippet) <= 80:
                failure = snippet[:80]
                return finalize(failure, 'body-snippet')

    # 6) Last resort: choose shortest unique line from diff_lines
    candidates = [l for l in diff_lines if 4 <= len(l) <= 150]
    if candidates:
        candidates.sort(key=len)
        failure = candidates[0][:80]
        return finalize(failure, 'fallback-line')
    
    # 7) If absolutely no error string found, use default
    failure = 'Login failed'
    return finalize(failure, 'default')


def build_hydra_command(host, path, post_string, userlist, passlist, failure):
    # hydra usage: hydra -L users.txt -P passes.txt host http-post-form "/path:params:FAIL_STRING"
    http_module = f'{path}:{post_string}:{failure}'
    return ['hydra', '-V', '-L', userlist, '-P', passlist, host, 'http-post-form', http_module, '-f']


def print_section(title):
    print(f"\n{Color.BOLD}{Color.GREEN}▸ {title}{Color.RESET}")


def print_kv(label, value, color=Color.YELLOW, indent='  '):
    print(f'{indent}{Color.BOLD}{label}{Color.RESET} : {color}{value}{Color.RESET}')


def print_wrapped(value, color=Color.YELLOW, indent='  ', continuation_indent='  ', width=76):
    lines = textwrap.wrap(value, width=width, break_long_words=True, break_on_hyphens=False)
    if not lines:
        print(f'{indent}{color}{value}{Color.RESET}')
        return
    for i, line in enumerate(lines):
        current_indent = indent if i == 0 else continuation_indent
        print(f'{current_indent}{color}{line}{Color.RESET}')


def extract_credentials_from_hydra(hydra_stdout, userlist_path):
    """Extract found credentials from hydra output."""
    import re
    creds = []
    
    # Rejoin lines that were broken by terminal wrapping
    lines_raw = hydra_stdout.splitlines()
    lines = []
    i = 0
    while i < len(lines_raw):
        line = lines_raw[i]
        # If line contains credential marker, check if it needs joining
        if '[' in line and 'password:' in line.lower():
            parts = line.split()
            password_val = None
            for j, p in enumerate(parts):
                if p.lower().startswith('password:'):
                    if ':' in p:
                        password_val = p.split(':', 1)[1]
                    elif j + 1 < len(parts):
                        password_val = parts[j + 1]
                    break
            
            # If password is missing or too short, join with next line
            if (not password_val or len(password_val) < 3) and i + 1 < len(lines_raw):
                next_line = lines_raw[i + 1].strip()
                if next_line and not next_line.startswith('['):
                    line = line + next_line
                    i += 2
                else:
                    i += 1
            else:
                i += 1
        else:
            i += 1
        
        lines.append(line)
    
    for line in lines:
        attempt_match = re.search(r'\[ATTEMPT\].*?login\s+"([^"]*)"\s+-\s+pass\s+"([^"]*)"', line, re.IGNORECASE)
        if attempt_match:
            continue

        # Hydra output format: [PORT][MODULE] host: TARGET   login: USER   password: PASS
        # or: [PORT][MODULE] host: TARGET   password: PASS (when no login field visible)
        if '[' in line and ']' in line and 'password:' in line.lower():
            pair_match = re.search(r'\blogin:\s*(\S+)\s+password:\s*(\S+)', line, re.IGNORECASE)
            if pair_match:
                creds.append((pair_match.group(1), pair_match.group(2)))
                continue

            pass_match = re.search(r'\bpassword:\s*(\S+)', line, re.IGNORECASE)
            if pass_match:
                creds.append(('(unknown)', pass_match.group(1)))
    
    return creds



def main():
    p = argparse.ArgumentParser(
        description='Detect login failure string from a URL (and optionally test credentials)'
    )
    p.add_argument('url', help='Target URL (e.g. https://example.com/login or example.com/login)')
    p.add_argument('--userlist', default=resolve_local_path('wordlists/usernames.txt'), help='Username wordlist (used only with --test)')
    p.add_argument('--passlist', default=resolve_local_path('wordlists/passwords.txt'), help='Password wordlist (used only with --test)')
    p.add_argument('--test', action='store_true', help='Also run hydra using the provided wordlists to test standard credentials')
    p.add_argument('-v', '--verbose', action='store_true', help='Verbose: show extra diagnostic info and timings')
    args = p.parse_args()

    args.userlist = resolve_local_path(args.userlist)
    args.passlist = resolve_local_path(args.passlist)

    target = args.url
    # normalize URL: if no scheme, default to http
    parsed_target = urlparse(target)
    if not parsed_target.scheme:
        url = f'http://{target}'
    else:
        url = target

    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        print(f"Failed to fetch URL {url}: {e}")
        sys.exit(2)
    page_content = resp.text
    page_url = resp.url
    soup = BeautifulSoup(page_content, 'html.parser')
    form = find_login_form(soup)

    if not form:
        print('No form found in the HTML file')
        sys.exit(3)

    username_field, password_field, other_fields = detect_fields(form)
    if not password_field:
        print('Could not detect password field in the form')
        sys.exit(4)

    action = form.get('action') or page_url
    method = (form.get('method') or 'get').lower()

    # Resolve action relative to the page URL
    if urlparse(action).netloc:
        full = action
    else:
        full = urljoin(page_url, action)

    parsed = urlparse(full)
    host = parsed.netloc
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query

    post_string = build_post_string(username_field, password_field, other_fields)

    # detect failure string automatically (required)
    session = requests.Session()
    if args.verbose:
        detected_failure, failure_details = detect_failure_string(
            session,
            full,
            method,
            username_field,
            password_field,
            other_fields,
            soup,
            return_details=True,
        )
    else:
        detected_failure = detect_failure_string(session, full, method, username_field, password_field, other_fields, soup)
        failure_details = None

    if not detected_failure:
        print('\nCould not automatically detect a failure string from the target page. Aborting.')
        print('Run with -v to see page differences and debug output.')
        sys.exit(7)

    failure_to_use = detected_failure

    # Output flow:
    # - default run (no --test): show failure detection string
    # - --test without -v: show only hydra command + execution + credentials
    # - -v: show failure detection details and detected fields in addition
    if (not args.test) or args.verbose:
        print_section('Failure Detection String')
        print(f'  {Color.YELLOW}{detected_failure}{Color.RESET}')

    if args.verbose and failure_details:
        print_section('Detection Details')
        print_kv('method', failure_details['method'])
        print_kv('submit url', failure_details['submit_url'])
        print_kv('response url', failure_details['response_url'])
        print_kv('status', failure_details['status_code'])
        print_kv('detected by', failure_details['detected_by'])

    # If user requested credential testing, build and run hydra
    if args.test:
        cmd_args = build_hydra_command(host, path, post_string, args.userlist, args.passlist, failure_to_use)
        cmd_display = shlex.join(cmd_args)
        print_section('Hydra Command')
        print_wrapped(cmd_display)

        # Show transient status while hydra runs; clear it after completion.
        show_transient_status = sys.stdout.isatty()
        if show_transient_status:
            status_line = f'  {Color.GREY}Running hydra... (press Ctrl-C to abort){Color.RESET}'
            print(status_line, end='', flush=True)

        import time
        start = time.perf_counter()
        proc = subprocess.run(cmd_args, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        duration = time.perf_counter() - start

        if show_transient_status:
            # Clear the transient line from terminal output.
            print('\r\033[2K\r', end='', flush=True)

        found_creds = extract_credentials_from_hydra(proc.stdout, args.userlist)

        if proc.returncode == 0 and found_creds:
            print_section('Found Credentials')
            for user, pwd in found_creds:
                print_kv('username', user, Color.YELLOW)
                print_kv('password', pwd, Color.YELLOW)
                print()
        else:
            print(f"{Color.RED}✗ No credentials found{Color.RESET}")

        if args.verbose:
            print_section('Hydra Output')
            print(f'  {Color.BOLD}stdout{Color.RESET}')
            print(proc.stdout or '(no stdout)')
            print(f'  {Color.BOLD}stderr{Color.RESET}')
            print(proc.stderr or '(no stderr)')
            print_section('Timings')
            print(f'  {Color.BOLD}runtime{Color.RESET} : {duration:.2f}s')
    # Show form analysis only in verbose mode
    if args.verbose:
        print_section('Detected fields')
        print_kv('username', username_field)
        print_kv('password', password_field)
        # Filter out "submit" type buttons to declutter output
        relevant_fields = [
            (n, v)
            for n, v in other_fields
            if not (n.lower() in ['login', 'anmelden', 'signin', 'submit'] and len(v) <= 20)
        ]
        for n, v in relevant_fields:
            print_kv(n, v)



if __name__ == '__main__':
    main()
