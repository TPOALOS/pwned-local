# pwned-local

**Find out whether a password is in a known breach list without sending it, or even its hash, anywhere.** The online range API leaks a hash
prefix to a third party. pwned-local checks passwords or SHA-1 hashes against a Have I Been Pwned style file you already have on disk
(`SHA1HEX:COUNT` per line, sorted ascending) using a seek-based binary search: constant memory, fine for tens-of-gigabytes files, no network
code at all. Passwords are never printed or logged.

Real output, against a three-line synthetic file made from obviously fake strings:

```
$ cat hashes.txt
16CECD982050D30B3D7EFEDD38F75C03C27807E6:7
193628DBAFF2733B494311E42E36EE48F0A6F350:4242
8F57C21DE98AFB5CE285A48060F0B7DD1BD20029:91
$ printf 'fake-password-one\n' | pwned-local -f hashes.txt --stdin
FOUND: seen 4242 times
$ printf 'something-else-example\n' | pwned-local -f hashes.txt --stdin
NOT FOUND
$ pwned-local -f hashes.txt --batch cands.txt
line 1: FOUND 7
line 2: not found
line 4: FOUND 4242
2 of 3 checked found
$ pwned-local -f hashes.txt --hash 16cecd982050d30b3d7efedd38f75c03c27807e6
FOUND: seen 7 times
$ pwned-local -f hashes.txt --password-arg fake-password-two
pwned-local: warning: --password-arg exposes the password in shell history and process listings; prefer the prompt or --stdin
FOUND: seen 7 times
```

(In `--batch` output the candidate passwords and their hashes are never shown, only line numbers; blank lines keep their numbering.)

## Getting the data (this tool does not download it)

pwned-local never contacts the network and has no downloader. The Have I Been Pwned passwords data set ("Pwned Passwords", SHA-1, ordered by
hash) is published by Troy Hunt's project. Get it yourself from the official source at haveibeenpwned.com (the Pwned Passwords page links the
torrent and the official downloader tool), check its licence and terms, and point `-f` at the resulting single sorted text file. The file must
be sorted ascending by hash; use `--verify-sorted` once to confirm (it streams the whole file).

## Usage

```
pwned-local -f HASHFILE                       # hidden prompt (getpass)
printf '%s\n' "$PW" | pwned-local -f HASHFILE --stdin
pwned-local -f HASHFILE --batch candidates.txt [--batch-hashes]    # '-' reads stdin
pwned-local -f HASHFILE --hash SHA1HEX [--hash SHA1HEX ...]
pwned-local -f HASHFILE --password-arg PASSWORD   # UNSAFE opt-in, warns
Options: --json  --max-batch N  --verify-sorted
```

Passwords are read from a hidden prompt, stdin, or a candidates file, never from a plain argument: command-line arguments end up in shell
history and the process list, so `--password-arg` exists only as an explicit, warned opt-in. Hash-file lines may use CRLF and either case.

## Exit codes

`0` not found, `1` found (or any batch line found), `2` usage or input error (bad hash file, bad hex, empty password, over-long or invalid batch
line, unsorted file with `--verify-sorted`).

## Limits

- Binary search assumes the file is sorted by the uppercase hex string. On an unsorted file it can silently miss entries; run `--verify-sorted`.
  Blank lines are tolerated only at the end of the file.
- "Not found" means "not in your file", not "safe". The list only covers known breaches and says nothing about password strength.
- A SHA-1 hash of a weak password is itself crackable; treat hashes you pass with `--hash` as sensitive too.
- Lines are capped at 4096 bytes (hash file) and candidates at 4096 bytes; batch size is capped (`--max-batch`, default 1,000,000).
- Passwords briefly exist in process memory and, with `--password-arg`, in argv; Python cannot reliably wipe them.
- Tested on small synthetic files only, not on the full multi-gigabyte data set.

MIT licensed.
