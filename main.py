#!/usr/bin/env python3
"""
A small, dependency-free URL normalizer & reducer — an approachable analog of "uro", but with a few extras.

Usage (Windows cmd.exe):
    python main.py -i file.txt -o out.txt

Optional flags:
    --aggressive           Collapse query parameter *values* (keep only keys). Helpful to de-duplicate lists with session IDs, hashes, etc.
    --strip-params RE      Regex of parameter names to drop (applied case-insensitively). Default drops common trackers: ^(?:utm_.*|fbclid|gclid|igshid|mc_cid|mc_eid|vero_id)$
    --keep-params NAMES    Comma-separated parameter names to *keep* even if they match --strip-params.
    --preserve-trailing    Preserve trailing slashes (by default paths are normalized, but trailing slash semantic is respected when present).
    --keep-fragment        Keep URL fragments (default: fragments removed).
    --input-encoding ENC   Input file encoding (default: utf-8).
    --output-encoding ENC  Output file encoding (default: utf-8).

What it does by default:
  • Lowercases scheme & host
  • Punycode-normalizes Internationalized Domain Names
  • Removes default ports (:80 for http, :443 for https)
  • Collapses duplicate slashes in path, resolves "/./" and "/../" safely
  • Removes fragments (#...)
  • Drops common tracking params (utm_*, fbclid, gclid, etc.)
  • Sorts query params by name + value for stable output
  • De-duplicates the results
  • Sorts final output alphabetically

Notes:
  • Lines that are blank or start with '#' are ignored.
  • If a line lacks a scheme but looks like a domain/path, we assume "http".
  • Non-URLish lines are passed through unchanged only if they contain at least one '/'; otherwise they are ignored (sane default for "word lists").
"""
from __future__ import annotations

import argparse
import io
import re
import sys
import posixpath
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

DEFAULT_STRIP_PARAMS = r"^(?:utm_.*|fbclid|gclid|yclid|igshid|mc_cid|mc_eid|vero_id|utm|utmcid|utmcsr|utmcmd|utmccn)$"

# Simple, permissive URL detector
URLISH = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*://|//)?[\w.-]+(?::\d+)?(?:/.*)?$")
MULTISLASH = re.compile(r"/{2,}")


def normalize_host(host: str) -> str:
    if not host:
        return host
    host = host.strip('.')  # strip surrounding dots
    # Lowercase and IDNA-punycode encode unicode labels
    try:
        # Split into labels to avoid encoding colons/ports
        if ':' in host:
            hostname, port = host.rsplit(':', 1)
            hostname_ascii = hostname.encode('idna').decode('ascii').lower()
            return f"{hostname_ascii}:{port}"
        else:
            return host.encode('idna').decode('ascii').lower()
    except Exception:
        return host.lower()


def normalize_path(path: str, preserve_trailing: bool) -> str:
    if path == '':
        return '/'
    trailing = path.endswith('/')
    # Collapse duplicate slashes (but keep a leading double slash in network-path refs later)
    p = MULTISLASH.sub('/', path)
    # Resolve dot segments
    p = posixpath.normpath(p)
    if not p.startswith('/'):
        p = '/' + p
    # Restore trailing slash if caller asked to preserve and it existed originally
    if preserve_trailing and trailing and not p.endswith('/'):
        p += '/'
    return p


def normalize_url(raw: str,
                  aggressive: bool = False,
                  strip_params: re.Pattern | None = None,
                  keep_params: set[str] | None = None,
                  preserve_trailing: bool = True,
                  keep_fragment: bool = False) -> str | None:
    s = raw.strip()
    if not s or s.startswith('#'):
        return None

    # Heuristic: add http:// if missing scheme but looks like a URL
    if '://' not in s and s.startswith('//'):
        s = 'http:' + s
    elif '://' not in s and URLISH.match(s):
        s = 'http://' + s

    try:
        parts = urlsplit(s)
    except Exception:
        return None

    scheme = (parts.scheme or 'http').lower()

    netloc = parts.netloc or ''
    # If input like "example.com:80" appeared in path (common), try to recover
    if not netloc and parts.path and ' ' not in parts.path:
        if '/' in parts.path:
            maybe_host, rest = parts.path.split('/', 1)
            if '.' in maybe_host:
                netloc = maybe_host
                new_path = '/' + rest
            else:
                new_path = parts.path
        else:
            maybe_host = parts.path
            new_path = '/'
        path = new_path
    else:
        path = parts.path or '/'

    netloc = normalize_host(netloc)

    # Remove default ports
    if ':' in netloc:
        host_only, port = netloc.rsplit(':', 1)
        if (scheme == 'http' and port == '80') or (scheme == 'https' and port == '443'):
            netloc = host_only

    path = normalize_path(path, preserve_trailing=preserve_trailing)

    # Query normalization
    qpairs = parse_qsl(parts.query, keep_blank_values=True)

    # Drop tracking params
    kept = []
    for k, v in qpairs:
        kn = k.lower()
        if keep_params and kn in keep_params:
            kept.append((kn, v if not aggressive else ''))
            continue
        if strip_params and strip_params.search(kn):
            continue
        kept.append((kn, v if not aggressive else ''))

    kept.sort(key=lambda kv: (kv[0], kv[1]))

    if aggressive:
        seen = set()
        compact = []
        for k, v in kept:
            if k in seen:
                continue
            seen.add(k)
            compact.append((k, ''))
        kept = compact

    query = urlencode(kept, doseq=True)

    fragment = parts.fragment if keep_fragment else ''

    return urlunsplit((scheme, netloc, path, query, fragment))


def process_stream(instream: io.TextIOBase,
                   outstream: io.TextIOBase,
                   **norm_kwargs) -> int:
    seen = set()
    for line in instream:
        norm = normalize_url(line, **norm_kwargs)
        if not norm:
            continue
        seen.add(norm)
    
    # sort alphabetically before writing
    written = 0
    for url in sorted(seen):
        outstream.write(url + "\n")
        written += 1
    return written


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="URL normalizer & reducer")
    p.add_argument('-i', '--input', dest='input', required=True, help='Path to input file (one URL per line)')
    p.add_argument('-o', '--output', dest='output', required=True, help='Path to output file')
    p.add_argument('--aggressive', action='store_true', help='Collapse values (keep only query keys) for stronger de-duplication')
    p.add_argument('--strip-params', default=DEFAULT_STRIP_PARAMS, help='Regex of parameter names to strip (case-insensitive)')
    p.add_argument('--keep-params', default='', help='Comma-separated list of param names to keep even if matched by --strip-params')
    p.add_argument('--preserve-trailing', action='store_true', help='Preserve trailing slash if present on input')
    p.add_argument('--keep-fragment', action='store_true', help='Keep URL fragments (#...)')
    p.add_argument('--input-encoding', default='utf-8', help='Encoding for input file (default utf-8)')
    p.add_argument('--output-encoding', default='utf-8', help='Encoding for output file (default utf-8)')

    args = p.parse_args(argv)

    keep_params = set([s.strip().lower() for s in args.keep_params.split(',') if s.strip()]) or None
    strip_params_re = re.compile(args.strip_params, flags=re.IGNORECASE)

    with open(args.input, 'r', encoding=args.input_encoding, errors='ignore') as fin, open(args.output, 'w', encoding=args.output_encoding, newline='') as fout:
        count = process_stream(
            fin,
            fout,
            aggressive=args.aggressive,
            strip_params=strip_params_re,
            keep_params=keep_params,
            preserve_trailing=args.preserve_trailing,
            keep_fragment=args.keep_fragment,
        )

    sys.stderr.write(f"Written {count} unique URL(s) to {args.output}\n")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
