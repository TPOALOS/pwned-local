import contextlib
import hashlib
import io
import json
import os
import socket
import tempfile
import unittest
from unittest import mock

import pwned_local as pl


def H(s):
    return hashlib.sha1(s.encode()).hexdigest().upper()


FAKE = ["fake-pass-%04d" % i for i in range(300)]


def make_file(path, words, newline="\n", lower=False, trailing_newline=True, counts=None, extra_tail=""):
    entries = sorted((H(w), (counts or {}).get(w, i + 1)) for i, w in enumerate(words))
    lines = []
    for h, c in entries:
        lines.append("%s:%d" % (h.lower() if lower else h, c))
    text = newline.join(lines)
    if trailing_newline and lines:
        text += newline
    text += extra_tail
    with open(path, "wb") as f:
        f.write(text.encode())
    return dict(entries)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "hashes.txt")

    def run_main(self, *argv, stdin=b"", getpass_value=None):
        out, err = io.StringIO(), io.StringIO()
        gp = mock.patch.object(pl.getpass, "getpass", return_value=getpass_value or "")
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), gp:
            try:
                code = pl.main(list(argv), stdin=io.BytesIO(stdin))
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()


class TestLookup(Base):
    def lookup(self, h):
        with pl.HashFile(self.path) as hf:
            return hf.count(h)

    def test_all_entries_found_with_counts(self):
        table = make_file(self.path, FAKE)
        for w in FAKE:
            self.assertEqual(self.lookup(H(w)), table[H(w)])

    def test_absent_entries(self):
        make_file(self.path, FAKE)
        for i in range(300, 400):
            self.assertIsNone(self.lookup(H("fake-pass-%04d" % i)))

    def test_single_entry(self):
        make_file(self.path, ["only-fake"])
        self.assertEqual(self.lookup(H("only-fake")), 1)
        self.assertIsNone(self.lookup(H("other-fake")))

    def test_two_entries(self):
        make_file(self.path, ["a-fake", "b-fake"])
        self.assertIsNotNone(self.lookup(H("a-fake")))
        self.assertIsNotNone(self.lookup(H("b-fake")))

    def test_empty_file(self):
        open(self.path, "wb").close()
        self.assertIsNone(self.lookup(H("x-fake")))

    def test_crlf(self):
        table = make_file(self.path, FAKE[:50], newline="\r\n")
        for w in FAKE[:50]:
            self.assertEqual(self.lookup(H(w)), table[H(w)])

    def test_lowercase_file(self):
        table = make_file(self.path, FAKE[:50], lower=True)
        # sorting of lower vs upper hex is identical for ASCII hex ordering of digits/letters? verify
        for w in FAKE[:50]:
            self.assertEqual(self.lookup(H(w)), table[H(w)])

    def test_lowercase_query(self):
        table = make_file(self.path, FAKE[:20])
        self.assertEqual(self.lookup(H(FAKE[3]).lower()), table[H(FAKE[3])])

    def test_no_trailing_newline(self):
        table = make_file(self.path, FAKE[:30], trailing_newline=False)
        last = sorted(H(w) for w in FAKE[:30])[-1]
        self.assertEqual(self.lookup(last), table[last])

    def test_trailing_blank_lines(self):
        table = make_file(self.path, FAKE[:30], extra_tail="\n\n\n")
        for w in FAKE[:30]:
            self.assertEqual(self.lookup(H(w)), table[H(w)])
        self.assertIsNone(self.lookup(H("nope-fake")))

    def test_missing_count_tolerated(self):
        h = H("nocount-fake")
        with open(self.path, "w") as f:
            f.write(h + "\n")
        self.assertEqual(self.lookup(h), 1)

    def test_large_counts(self):
        make_file(self.path, ["big-fake"], counts={"big-fake": 10 ** 12})
        self.assertEqual(self.lookup(H("big-fake")), 10 ** 12)

    def test_malformed_line_raises(self):
        with open(self.path, "w") as f:
            f.write("not-a-hash:5\n" * 5)
        with self.assertRaises(pl.FormatError):
            self.lookup(H("x"))

    def test_binary_garbage_raises_or_none(self):
        with open(self.path, "wb") as f:
            f.write(os.urandom(5000))
        try:
            self.lookup(H("x"))
        except pl.FormatError:
            pass

    def test_overlong_line_raises(self):
        with open(self.path, "wb") as f:
            f.write(b"A" * 20000)
        with self.assertRaises(pl.FormatError):
            self.lookup(H("x"))

    def test_bad_count_raises(self):
        with open(self.path, "w") as f:
            f.write(H("a-fake") + ":abc\n")
        with self.assertRaises(pl.FormatError):
            self.lookup(H("a-fake"))

    def test_seek_based_does_not_read_whole_file(self):
        make_file(self.path, ["w%05d" % i for i in range(5000)])
        reads = []
        with pl.HashFile(self.path) as hf:
            orig = hf.f.read
            hf.f.read = lambda n=-1: (reads.append(n), orig(n))[1]
            orig_rl = hf.f.readline
            hf.f.readline = lambda n=-1: (reads.append(n), orig_rl(n))[1]
            hf.count(H("w00042"))
        self.assertTrue(all(n != -1 for n in reads))
        self.assertLess(len(reads), 80)

    def test_parse_line_helper(self):
        self.assertIsNone(pl.parse_line(b"  \r\n"))
        self.assertEqual(pl.parse_line((H("z") + ":7\r\n").encode()), (H("z"), 7))

    def test_hashfile_rejects_directory(self):
        with self.assertRaises(pl.FormatError):
            pl.HashFile(self.tmp.name)


class TestVerifySorted(Base):
    def test_sorted_ok(self):
        make_file(self.path, FAKE[:40])
        self.assertEqual(pl.verify_sorted(self.path), 40)

    def test_unsorted_detected(self):
        hs = sorted(H(w) for w in FAKE[:10])
        hs[0], hs[5] = hs[5], hs[0]
        with open(self.path, "w") as f:
            f.write("\n".join(h + ":1" for h in hs) + "\n")
        with self.assertRaises(pl.FormatError):
            pl.verify_sorted(self.path)

    def test_cli_verify_sorted_flag(self):
        hs = [H("b-fake"), H("a-fake")]
        hs.sort(reverse=True)
        with open(self.path, "w") as f:
            f.write("\n".join(h + ":1" for h in hs) + "\n")
        code, _, err = self.run_main("-f", self.path, "--verify-sorted", "--hash", H("a-fake"))
        self.assertEqual(code, 2)
        self.assertIn("not sorted", err)


class TestCliPassword(Base):
    def setUp(self):
        super().setUp()
        self.table = make_file(self.path, FAKE)

    def test_stdin_found_exit_1(self):
        code, out, _ = self.run_main("-f", self.path, "--stdin", stdin=(FAKE[7] + "\n").encode())
        self.assertEqual(code, 1)
        self.assertIn("FOUND: seen %d times" % self.table[H(FAKE[7])], out)

    def test_stdin_not_found_exit_0(self):
        code, out, _ = self.run_main("-f", self.path, "--stdin", stdin=b"unlisted-fake\n")
        self.assertEqual(code, 0)
        self.assertIn("NOT FOUND", out)

    def test_stdin_crlf(self):
        code, _, _ = self.run_main("-f", self.path, "--stdin", stdin=(FAKE[1] + "\r\n").encode())
        self.assertEqual(code, 1)

    def test_stdin_preserves_inner_spaces(self):
        make_file(self.path, ["with space fake "])
        code, _, _ = self.run_main("-f", self.path, "--stdin", stdin=b"with space fake \n")
        self.assertEqual(code, 1)

    def test_stdin_empty_exit_2(self):
        code, _, err = self.run_main("-f", self.path, "--stdin", stdin=b"")
        self.assertEqual(code, 2)

    def test_stdin_too_long(self):
        code, _, _ = self.run_main("-f", self.path, "--stdin", stdin=b"x" * 10000 + b"\n")
        self.assertEqual(code, 2)

    def test_prompt_mode(self):
        code, out, _ = self.run_main("-f", self.path, getpass_value=FAKE[2])
        self.assertEqual(code, 1)

    def test_prompt_empty(self):
        code, _, _ = self.run_main("-f", self.path, getpass_value="")
        self.assertEqual(code, 2)

    def test_password_arg_warns_and_works(self):
        code, out, err = self.run_main("-f", self.path, "--password-arg", FAKE[9])
        self.assertEqual(code, 1)
        self.assertIn("shell history", err)

    def test_password_never_printed(self):
        secret = FAKE[11]
        for argv, stdin in ((("--stdin",), (secret + "\n").encode()),
                            (("--password-arg", secret), b""),
                            (("--stdin", "--json"), (secret + "\n").encode())):
            code, out, err = self.run_main("-f", self.path, *argv, stdin=stdin)
            self.assertNotIn(secret, out + err)
            self.assertNotIn(H(secret), out + err)
            self.assertNotIn(H(secret).lower(), out + err)

    def test_json_output(self):
        code, out, _ = self.run_main("-f", self.path, "--stdin", "--json", stdin=(FAKE[4] + "\n").encode())
        d = json.loads(out)
        self.assertTrue(d["found"])
        self.assertEqual(d["count"], self.table[H(FAKE[4])])
        self.assertEqual(set(d), {"found", "count"})

    def test_unicode_password(self):
        make_file(self.path, ["päss-fake-☃"])
        code, _, _ = self.run_main("-f", self.path, "--stdin", stdin="päss-fake-☃\n".encode())
        self.assertEqual(code, 1)

    def test_invalid_utf8_stdin_does_not_crash(self):
        code, _, _ = self.run_main("-f", self.path, "--stdin", stdin=b"\xff\xfe-bad\n")
        self.assertEqual(code, 0)

    def test_conflicting_sources(self):
        code, _, _ = self.run_main("-f", self.path, "--stdin", "--hash", H("a"))
        self.assertEqual(code, 2)

    def test_missing_hash_file(self):
        code, _, err = self.run_main("-f", os.path.join(self.tmp.name, "nope"), "--stdin", stdin=b"x\n")
        self.assertEqual(code, 2)

    def test_hash_file_required(self):
        code, _, _ = self.run_main("--stdin")
        self.assertEqual(code, 2)

    def test_malformed_hash_file_exit_2(self):
        with open(self.path, "w") as f:
            f.write("garbage\n" * 10)
        code, _, err = self.run_main("-f", self.path, "--stdin", stdin=b"x\n")
        self.assertEqual(code, 2)
        self.assertIn("malformed", err)

    def test_no_network_used(self):
        def boom(*a, **k):
            raise AssertionError("network used")
        with mock.patch.object(socket, "socket", boom), \
                mock.patch.object(socket, "create_connection", boom), \
                mock.patch.object(socket, "getaddrinfo", boom):
            code, _, _ = self.run_main("-f", self.path, "--stdin", stdin=(FAKE[0] + "\n").encode())
        self.assertEqual(code, 1)

    def test_module_imports_no_network_libs(self):
        with open(pl.__file__) as fh:
            src = fh.read()
        for bad in ("urllib", "http.client", "requests", "import socket", "ftplib"):
            self.assertNotIn(bad, src)


class TestCliHash(Base):
    def setUp(self):
        super().setUp()
        self.table = make_file(self.path, FAKE)

    def test_hash_found(self):
        code, out, _ = self.run_main("-f", self.path, "--hash", H(FAKE[5]))
        self.assertEqual(code, 1)
        self.assertIn("FOUND", out)

    def test_hash_lower(self):
        code, _, _ = self.run_main("-f", self.path, "--hash", H(FAKE[5]).lower())
        self.assertEqual(code, 1)

    def test_hash_not_found(self):
        code, out, _ = self.run_main("-f", self.path, "--hash", H("zz-nothere"))
        self.assertEqual(code, 0)
        self.assertIn("NOT FOUND", out)

    def test_hash_invalid(self):
        for bad in ("abc", "g" * 40, H("x") + "0", ""):
            code, _, _ = self.run_main("-f", self.path, "--hash", bad)
            self.assertEqual(code, 2, bad)

    def test_hash_multiple_json(self):
        code, out, _ = self.run_main("-f", self.path, "--hash", H(FAKE[1]), "--hash", H("zz-nothere"), "--json")
        d = json.loads(out)
        self.assertEqual([r["found"] for r in d["results"]], [True, False])
        self.assertEqual(code, 1)

    def test_hash_json_single(self):
        _, out, _ = self.run_main("-f", self.path, "--hash", H(FAKE[1]), "--json")
        d = json.loads(out)
        self.assertEqual(d["count"], self.table[H(FAKE[1])])
        self.assertEqual(d["sha1"], H(FAKE[1]))


class TestCliBatch(Base):
    def setUp(self):
        super().setUp()
        self.table = make_file(self.path, FAKE)
        self.cand = os.path.join(self.tmp.name, "cands.txt")

    def write_cands(self, data):
        with open(self.cand, "wb") as f:
            f.write(data)

    def test_batch_counts_by_line_number_only(self):
        self.write_cands((FAKE[3] + "\nunlisted-fake\n" + FAKE[4] + "\n").encode())
        code, out, err = self.run_main("-f", self.path, "--batch", self.cand)
        self.assertEqual(code, 1)
        self.assertIn("line 1: FOUND %d" % self.table[H(FAKE[3])], out)
        self.assertIn("line 2: not found", out)
        self.assertIn("line 3: FOUND", out)
        self.assertNotIn(FAKE[3], out + err)
        self.assertNotIn(H(FAKE[3]), out + err)
        self.assertIn("2 of 3 checked found", out)

    def test_batch_json(self):
        self.write_cands((FAKE[3] + "\nzzz-unlisted\n").encode())
        code, out, _ = self.run_main("-f", self.path, "--batch", self.cand, "--json")
        d = json.loads(out)
        self.assertEqual(d["results"][0], {"line": 1, "found": True, "count": self.table[H(FAKE[3])]})
        self.assertEqual(d["results"][1]["found"], False)
        self.assertNotIn(FAKE[3], out)
        self.assertNotIn(H(FAKE[3]), out)

    def test_batch_all_clean_exit_0(self):
        self.write_cands(b"unlisted-a\nunlisted-b\n")
        code, _, _ = self.run_main("-f", self.path, "--batch", self.cand)
        self.assertEqual(code, 0)

    def test_batch_blank_lines_keep_numbering(self):
        self.write_cands(("\n\n" + FAKE[0] + "\n").encode())
        _, out, _ = self.run_main("-f", self.path, "--batch", self.cand)
        self.assertIn("line 3: FOUND", out)

    def test_batch_crlf(self):
        self.write_cands((FAKE[0] + "\r\n" + FAKE[1] + "\r\n").encode())
        _, out, _ = self.run_main("-f", self.path, "--batch", self.cand)
        self.assertIn("2 of 2", out)

    def test_batch_no_trailing_newline(self):
        self.write_cands(FAKE[0].encode())
        code, _, _ = self.run_main("-f", self.path, "--batch", self.cand)
        self.assertEqual(code, 1)

    def test_batch_stdin(self):
        code, out, _ = self.run_main("-f", self.path, "--batch", "-", stdin=(FAKE[2] + "\n").encode())
        self.assertEqual(code, 1)

    def test_batch_binary_lines_do_not_crash(self):
        self.write_cands(b"\xff\xfe\x00\x01\nplain\n" + os.urandom(64).replace(b"\n", b"") + b"\n")
        code, _, _ = self.run_main("-f", self.path, "--batch", self.cand)
        self.assertEqual(code, 0)

    def test_batch_overlong_line_is_error(self):
        self.write_cands(b"x" * 100000 + b"\n" + FAKE[0].encode() + b"\n")
        code, out, _ = self.run_main("-f", self.path, "--batch", self.cand)
        self.assertEqual(code, 2)
        self.assertIn("line 1: ERROR line too long", out)
        self.assertIn("line 2: FOUND", out)

    def test_batch_max_lines(self):
        self.write_cands(b"a\nb\nc\n")
        code, _, err = self.run_main("-f", self.path, "--batch", self.cand, "--max-batch", "2")
        self.assertEqual(code, 2)

    def test_batch_missing_file(self):
        code, _, _ = self.run_main("-f", self.path, "--batch", os.path.join(self.tmp.name, "nope"))
        self.assertEqual(code, 2)

    def test_batch_hashes(self):
        self.write_cands((H(FAKE[6]).lower() + "\n" + H("none-fake") + "\n").encode())
        code, out, _ = self.run_main("-f", self.path, "--batch", self.cand, "--batch-hashes")
        self.assertEqual(code, 1)
        self.assertIn("line 1: FOUND", out)
        self.assertIn("line 2: not found", out)

    def test_batch_hashes_invalid_line(self):
        self.write_cands(b"not-hex\n")
        code, out, _ = self.run_main("-f", self.path, "--batch", self.cand, "--batch-hashes")
        self.assertEqual(code, 2)
        self.assertIn("ERROR", out)

    def test_batch_hashes_requires_batch(self):
        code, _, _ = self.run_main("-f", self.path, "--batch-hashes", "--hash", H("a"))
        self.assertEqual(code, 2)

    def test_read_candidates_helper(self):
        got = list(pl.read_candidates(io.BytesIO(b"a\r\nb\n\nc"), 10))
        self.assertEqual(got, [(1, b"a"), (2, b"b"), (3, b""), (4, b"c")])


if __name__ == "__main__":
    unittest.main()
