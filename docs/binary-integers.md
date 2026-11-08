# Built-in Bytes integer reads

`Bytes` is a built-in Rut type. Its fixed-width integer methods combine raw
octets with explicit byte order. No import, protocol library, new keyword or
external dependency is required.

```rut
route POST "/number" {
    guard let value = req.bodyBytes.readU16BE(0) else { return 400 }
    guard value == 300 else { return 422 }
    return 204
}
```

See the executable [big/little endian example](../examples/bytes-integers.rut).

| Big endian method | Little endian method | Width | Result and range |
| --- | --- | --- | --- |
| `bytes.readU16BE(offset)` | `bytes.readU16LE(offset)` | 2 bytes | `i32?`, 0–65535 |
| `bytes.readI16BE(offset)` | `bytes.readI16LE(offset)` | 2 bytes | `i32?`, −32768–32767 |
| `bytes.readU32BE(offset)` | `bytes.readU32LE(offset)` | 4 bytes | `i64?`, 0–4294967295 |
| `bytes.readI32BE(offset)` | `bytes.readI32LE(offset)` | 4 bytes | `i32?`, −2147483648–2147483647 |
| `bytes.readI64BE(offset)` | `bytes.readI64LE(offset)` | 8 bytes | `i64?`, −9223372036854775808–9223372036854775807 |

`BE` puts the most significant byte first: `b"\x01\x2c"` represents 300.
`LE` puts it last: `b"\x2c\x01"` represents 300. Signed readers interpret
two's complement. The results are independent of the host's byte order and
support unaligned offsets.

Receivers must be unwrapped Bytes. Offsets are unwrapped `i32` values, starting
at zero. Negative offsets, missing bytes and offsets outside the buffer return
nil. Bounds are checked using
`length >= width` and `0 <= offset <= length - width` before forming/loading
addresses. Reads do not modify the Bytes, advance a cursor, perform I/O,
allocate memory or change `netError()`. Callers explicitly choose each offset.
NUL bytes and high-bit bytes have their full binary meaning.

Unsigned 32-bit readers produce i64 values, preserving values above 2147483647.
Source `i64` annotations remain unsupported. Unsigned 64-bit values above
9223372036854775807 cannot fit Rut's implemented signed scalar types. There is
no unsigned 64-bit reader or silent narrowing to negative values; supporting
that full range needs a separate numeric-type design.

TCP callers must first acquire a complete field using `readExactly` or an
existing buffered protocol read. The decoders accept the returned Bytes but do
not fetch additional data. UDP callers can decode fields in a received datagram
using explicit offsets. These methods do not add variable-length integer
encoding, floating point decoding, serialization or streaming parser loops.

The compiler validates exact receiver/offset types and lowers these methods to
bounds-checked scalar operations shared by JIT and native compilation. Loads
assemble individual octets, avoiding alignment and host-endian assumptions.
Signed 16-bit reads sign-extend; unsigned 32-bit reads retain a nonnegative i64.

Tests compare all ten readers against Python's `struct` codec over deterministic
random and boundary values on epoll and io_uring at optimization levels 0 and 2.
They cover truncation, empty input, negative/extreme offsets, unaligned fields,
wrong expected values, the
full unsigned 32-bit range, and native execution after removing the source.
