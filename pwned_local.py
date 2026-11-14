#!/usr/bin/env python3
"""pwned-local: check passwords or SHA-1 hashes against a LOCAL Have I Been Pwned
style sorted hash file ("SHA1HEX:COUNT" per line, ascending by hash).

Never uses the network. Uses a seek-based binary search, so memory use is
constant regardless of file size. Passwords are never printed or logged.

Exit codes: 0 not found / clean, 1 found in the list, 2 usage or input error.
"""
import argparse
import getpass
import hashlib
import json
import os
import re
import stat
import sys

__version__ = "1.0.0"

MAX_LINE = 4096          # longest hash-file line we accept
MAX_CANDIDATE = 4096     # longest candidate password line (bytes)
DEFAULT_MAX_BATCH = 1000000
HEX40 = re.compile(r"^[0-9A-Fa-f]{40}$")


class FormatError(Exception):
    pass


def sha1_hex(data):
    return hashlib.sha1(data).hexdigest().upper()


def parse_line(raw):
    """Parse a hash-file line (bytes). Returns (HEX upper str, count) or None for blank."""
    line = raw.rstrip(b"\r\n").strip()
    if not line:
        return None
    key, sep, rest = line.partition(b":")
    try:
        key_s = key.decode("ascii").upper()
    except UnicodeDecodeError:
        raise FormatError("non-ASCII data in hash file")
    if not HEX40.match(key_s):
        raise FormatError("malformed line in hash file (expected 40 hex chars)")
    if not sep:
        return key_s, 1
    try:
        count = int(rest.strip().decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        raise FormatError("malformed count in hash file")
    if count < 0:
        raise FormatError("negative count in hash file")
    return key_s, count


def _line_start(f, pos, floor=0):
    """Offset of the start of the line containing byte offset pos."""
    scanned = 0
    cur = pos
    while cur > floor:
        step = min(256, cur - floor)
        f.seek(cur - step)
        chunk = f.read(step)
        i = chunk.rfind(b"\n")
        if i >= 0:
            return cur - step + i + 1
        cur -= step
        scanned += step
        if scanned > MAX_LINE:
            raise FormatError("line longer than %d bytes (not a hash file?)" % MAX_LINE)
    return floor


def lookup(f, size, target_hex):
    """Binary search an open binary file. Returns count (int) or None if absent."""
    target = target_hex.upper()
    lo, hi = 0, size
    while lo < hi:
        mid = (lo + hi) // 2
        start = _line_start(f, mid, lo)
        f.seek(start)
        raw = f.readline(MAX_LINE + 1)
        if len(raw) > MAX_LINE:
            raise FormatError("line longer than %d bytes (not a hash file?)" % MAX_LINE)
        parsed = parse_line(raw)
        if parsed is None:
            # blank lines are tolerated only at the end of the file
            hi = start
            continue
        key, count = parsed
        if key == target:
            return count
        if key < target:
            lo = start + len(raw)
        else:
            hi = start
    return None


class HashFile:
    def __init__(self, path):
        try:
            self.f = open(path, "rb")
        except OSError as exc:
            raise FormatError("cannot open hash file: %s" % (exc.strerror or exc))
        st = os.fstat(self.f.fileno())
        if not stat.S_ISREG(st.st_mode):
            self.f.close()
            raise FormatError("hash file is not a regular file")
        self.size = st.st_size

    def count(self, hex_hash):
        return lookup(self.f, self.size, hex_hash)

    def close(self):
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def verify_sorted(path):
    """Stream the whole file once and confirm it is sorted and well formed. Returns line count."""
    prev = None
    n = 0
    with open(path, "rb") as f:
        while True:
            raw = f.readline(MAX_LINE + 1)
            if not raw:
                break
            if len(raw) > MAX_LINE:
                raise FormatError("line %d longer than %d bytes" % (n + 1, MAX_LINE))
            n += 1
            p = parse_line(raw)
            if p is None:
                continue
            if prev is not None and p[0] < prev:
                raise FormatError("file is not sorted ascending (line %d)" % n)
            prev = p[0]
    return n


def read_candidates(fobj, max_lines):
    """Yield (line_number, bytes) from a binary stream. Lines too long yield None as data."""
    n = 0
    while True:
        raw = fobj.readline(MAX_CANDIDATE + 2)
        if not raw:
            return
        n += 1
        if n > max_lines:
            raise FormatError("more than %d lines in batch input" % max_lines)
        if len(raw) > MAX_CANDIDATE + 1 and not raw.endswith(b"\n"):
            # drain the rest of the oversized line
            while True:
                more = fobj.readline(65536)
                if not more or more.endswith(b"\n"):
                    break
            yield n, None
            continue
        if raw.endswith(b"\n"):
            raw = raw[:-1]
            if raw.endswith(b"\r"):
                raw = raw[:-1]
        yield n, raw


def build_parser():
    p = argparse.ArgumentParser(
        prog="pwned-local",
        description="Check passwords or SHA-1 hashes against a local HIBP-style sorted hash file. "
                    "Never contacts the network; never prints passwords.",
        epilog="Exit codes: 0 not found, 1 found, 2 usage/input error.")
    p.add_argument("-f", "--file", required=True, metavar="HASHFILE",
                   help="local sorted file of SHA1HEX:COUNT lines")
    src = p.add_argument_group("input (default: hidden prompt)")
    src.add_argument("--stdin", action="store_true", help="read ONE password from the first line of stdin")
    src.add_argument("--batch", metavar="FILE",
                     help="file of candidates, one per line ('-' for stdin); reports counts per line number only")
    src.add_argument("--batch-hashes", action="store_true",
                     help="treat --batch lines as SHA-1 hex instead of passwords")
    src.add_argument("--hash", metavar="SHA1HEX", action="append",
                     help="check a SHA-1 hex digest directly (repeatable)")
    src.add_argument("--password-arg", metavar="PASSWORD",
                     help="UNSAFE: pass a password on the command line (leaks into shell history and ps)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--max-batch", type=int, default=DEFAULT_MAX_BATCH,
                   help="maximum lines accepted in a batch (default %d)" % DEFAULT_MAX_BATCH)
    p.add_argument("--verify-sorted", action="store_true",
                   help="first stream the whole hash file to confirm it is sorted and well formed")
    p.add_argument("--version", action="version", version="pwned-local " + __version__)
    return p


def emit(args, payload, text_lines):
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for t in text_lines:
            print(t)


def main(argv=None, stdin=None):
    args = build_parser().parse_args(argv)
    in_stream = stdin if stdin is not None else sys.stdin.buffer

    modes = [bool(args.stdin), args.batch is not None, bool(args.hash), args.password_arg is not None]
    if sum(modes) > 1:
        print("pwned-local: choose only one input source (--stdin, --batch, --hash, --password-arg)",
              file=sys.stderr)
        return 2
    if args.batch_hashes and args.batch is None:
        print("pwned-local: --batch-hashes requires --batch", file=sys.stderr)
        return 2
    if args.max_batch < 1:
        print("pwned-local: --max-batch must be positive", file=sys.stderr)
        return 2
    if args.batch == "-" and args.stdin:
        print("pwned-local: stdin used twice", file=sys.stderr)
        return 2

    try:
        if args.verify_sorted:
            verify_sorted(args.file)
        hf = HashFile(args.file)
    except (FormatError, OSError) as exc:
        print("pwned-local: %s" % (exc if isinstance(exc, FormatError) else exc.strerror), file=sys.stderr)
        return 2

    try:
        with hf:
            if args.batch is not None:
                return run_batch(args, hf, in_stream)
            if args.hash:
                return run_hashes(args, hf)
            if args.password_arg is not None:
                print("pwned-local: warning: --password-arg exposes the password in shell history and "
                      "process listings; prefer the prompt or --stdin", file=sys.stderr)
                pw = args.password_arg.encode("utf-8", "surrogateescape")
            elif args.stdin:
                raw = in_stream.readline(MAX_CANDIDATE + 2)
                pw = raw.rstrip(b"\n")
                if pw.endswith(b"\r"):
                    pw = pw[:-1]
                if len(raw) > MAX_CANDIDATE + 1:
                    print("pwned-local: password on stdin too long", file=sys.stderr)
                    return 2
            else:
                try:
                    pw = getpass.getpass("Password (input hidden): ").encode("utf-8", "surrogateescape")
                except (EOFError, KeyboardInterrupt):
                    print("pwned-local: no password entered", file=sys.stderr)
                    return 2
            if not pw:
                print("pwned-local: empty password", file=sys.stderr)
                return 2
            count = hf.count(sha1_hex(pw))
            found = count is not None
            emit(args, {"found": found, "count": count or 0},
                 ["FOUND: seen %d times" % count if found else "NOT FOUND"])
            return 1 if found else 0
    except FormatError as exc:
        print("pwned-local: %s" % exc, file=sys.stderr)
        return 2


def run_hashes(args, hf):
    results = []
    bad = False
    for h in args.hash:
        h = h.strip()
        if not HEX40.match(h):
            print("pwned-local: not a 40-character SHA-1 hex digest", file=sys.stderr)
            return 2
        c = hf.count(h)
        results.append({"sha1": h.upper(), "found": c is not None, "count": c or 0})
    found = any(r["found"] for r in results)
    lines = ["%s %s" % (r["sha1"], "FOUND: seen %d times" % r["count"] if r["found"] else "NOT FOUND")
             for r in results]
    if len(results) == 1 and not args.json:
        lines = [lines[0].split(" ", 1)[1]]
    emit(args, results[0] if len(results) == 1 else {"results": results}, lines)
    return 1 if found else 0


def run_batch(args, hf, in_stream):
    if args.batch == "-":
        src = in_stream
        closer = None
    else:
        try:
            src = open(args.batch, "rb")
        except OSError as exc:
            print("pwned-local: cannot open batch file: %s" % (exc.strerror or exc), file=sys.stderr)
            return 2
        closer = src
    results = []
    errors = 0
    try:
        for n, raw in read_candidates(src, args.max_batch):
            if raw is None:
                results.append({"line": n, "error": "line too long"})
                errors += 1
                continue
            if raw == b"":
                continue
            if args.batch_hashes:
                try:
                    digest = raw.decode("ascii").strip()
                except UnicodeDecodeError:
                    digest = ""
                if not HEX40.match(digest):
                    results.append({"line": n, "error": "not a SHA-1 hex digest"})
                    errors += 1
                    continue
                digest = digest.upper()
            else:
                digest = sha1_hex(raw)
            c = hf.count(digest)
            results.append({"line": n, "found": c is not None, "count": c or 0})
    finally:
        if closer:
            closer.close()
    found = any(r.get("found") for r in results)
    lines = []
    for r in results:
        if "error" in r:
            lines.append("line %d: ERROR %s" % (r["line"], r["error"]))
        elif r["found"]:
            lines.append("line %d: FOUND %d" % (r["line"], r["count"]))
        else:
            lines.append("line %d: not found" % r["line"])
    summary_found = sum(1 for r in results if r.get("found"))
    lines.append("%d of %d checked found" % (summary_found, sum(1 for r in results if "error" not in r)))
    emit(args, {"results": results, "found": summary_found,
                "checked": sum(1 for r in results if "error" not in r), "errors": errors}, lines)
    if errors:
        return 2
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
