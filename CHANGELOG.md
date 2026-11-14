# Changelog

## 1.0.0

First release.

- Offline binary search over a local sorted "SHA1HEX:COUNT" file (seek-based, constant memory)
- Passwords from a hidden prompt, stdin, or a candidates file; never from argv unless `--password-arg`
- `--hash` for SHA-1 hex input, `--batch FILE` with per-line counts only, `--json`
