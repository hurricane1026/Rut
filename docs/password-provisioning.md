# Password provisioning

`rut-password` is an offline administrative tool. It uses the runtime's existing
fixed PBKDF2-HMAC-SHA256 profile and OS-generated random salt, without LLVM or new
dependencies. It does not start a gateway, register accounts or run on a shard.

Build and inspect its interface:

```sh
cmake --build build --target rut-password
build/src/rut-password --help
```

Create a private directory and a new record. On a terminal, the tool prompts for
the password with echo disabled; Enter ends the input and is omitted. The tool
restores terminal settings on normal completion, read errors and caught
SIGINT/SIGTERM/SIGHUP. Password scratch is cleansed before exit.

```sh
mkdir -m 700 credentials
build/src/rut-password hash --output credentials/alice.record
build/src/rut-password verify credentials/alice.record
```

Passwords are accepted only from stdin. There is no plaintext password argument
or environment option. Redirected/piped input is 1–1024 **exact bytes**, read to
EOF, with embedded NUL, whitespace and newlines preserved. A trailing newline in
redirected input is part of the password; empty or oversized input fails without
publishing a record. Terminal input additionally follows the terminal driver's
configured erase and kill keys; its configured EOF key ends input. Echo remains
disabled while a bounded noncanonical reader enforces the same 1–1024 byte
limit without depending on the platform's canonical-line buffer. Over-limit
lines are drained through Enter/EOF without storing the remaining bytes, so
echo stays disabled until the line ends. Enter is still mapped according to the
terminal's input settings. For arbitrary bytes, use redirected input from an
existing secret-delivery channel.

`hash` without `--output` writes exactly a canonical 123-byte record plus one LF
to stdout. With `--output`, stdout remains empty. `verify` accepts a canonical
regular file containing 123 bytes or 124 bytes with exactly one final LF. It
rejects final-component symlinks, directories, FIFOs, extra whitespace/newlines,
unsupported profiles and malformed records. Verification reads a bounded snapshot;
it does not lock files against unrelated external writers.

Exit codes are `0` for successful creation or a password match, `1` for a
well-formed record whose password does not match, and `2` for usage, input,
cancellation, filesystem or crypto errors. Verification prints no password,
record or success token. Diagnostics go to stderr and never include credentials.

## File publication

`hash --output` creates a **new** file with mode `0600`, independent of a
permissive umask. The immediate parent must be owned by the current effective
user and have no group/other write permission. Directory components may resolve
through symlinks; the directory is opened and validated, then all publication
operations use that descriptor. Existing destination files, symlinks and special
files are never overwritten. Competing creators publish at most one winner.

The tool writes a private same-directory temporary file, sets its mode, syncs
and closes it, atomically hard-links it into the previously absent destination,
removes the temporary name and syncs the directory. The temporary name uses the
new record's public random salt; plaintext is never written to a temporary file.
This requires filesystem support for hard links and file/directory `fsync`.
Successful persistence follows those OS/filesystem guarantees; this is not a
cross-filesystem transaction or a credential database.

Failures before publication leave the destination absent or unchanged. An error
after publication can leave a complete record at the destination; diagnostics
explicitly report this case instead of deleting the published record. A crash
or uncatchable signal may leave a private `.rut-password-*` temporary record.
There is no automatic overwrite, password change/reset or orphan-file collector.

## Use with the login example

Load the public verifier record into the existing compile-time configuration:

```sh
export PASSWORD_HASH="$(cat credentials/alice.record)"
export PASSWORD_SUBJECT=alice
```

Supply `JWT_ISSUE_KEY` through your deployment's secret-delivery mechanism and
start [password-jwt-login.rut](../examples/password-jwt-login.rut) over TLS as
described in the [language card](language-card.md#fixed-account-passwordjwt-composition).
The record and signing key are captured at compilation/load time; editing a file
does not mutate a running configuration. Verifier records support offline
guessing and need protected storage even though they contain no plaintext.

Choose passwords representable by the credential transport. The login example's
HTTP header applies normal field-value trimming and rejects CR/LF/NUL; arbitrary
binary CLI/native passwords are not automatically usable through that header.

This tool supplies provisioning for the fixed-account profile. Durable account
registration, user lookup, password change/reset, rehash migration, session
refresh/logout and revocation persistence remain separate work.
