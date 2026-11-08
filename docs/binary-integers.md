# Reading binary integers

Import the ordinary Rut [binary helper library](../examples/clients/binary.rut)
to combine Bytes into integers. This builds on checked byte subscripts and
existing integer arithmetic; it adds no keywords, numeric types, native client
operations or dependencies.

```rut
import "clients/binary.rut"

route POST "/number" {
    guard let value = binary.readU16BE(req.bodyBytes, 0) else { return 400 }
    guard value == 300 else { return 422 }
    return 204
}
```

The import above is relative to the source file. See the executable
[big/little endian example](../examples/bytes-integers.rut).

| Big endian helper | Little endian helper | Width | Result and range |
| --- | --- | --- | --- |
| `readU16BE(bytes, offset)` | `readU16LE(bytes, offset)` | 2 bytes | `i32?`, 0–65535 |
| `readI16BE(bytes, offset)` | `readI16LE(bytes, offset)` | 2 bytes | `i32?`, −32768–32767 |
| `readU32BE(bytes, offset)` | `readU32LE(bytes, offset)` | 4 bytes | `i64?`, 0–4294967295 |
| `readI32BE(bytes, offset)` | `readI32LE(bytes, offset)` | 4 bytes | `i32?`, −2147483648–2147483647 |
| `readI64BE(bytes, offset)` | `readI64LE(bytes, offset)` | 8 bytes | `i64?`, −9223372036854775808–9223372036854775807 |

`BE` puts the most significant byte first: `b"\x01\x2c"` represents 300.
`LE` puts it last: `b"\x2c\x01"` represents 300. Signed readers interpret
two's complement. The results are independent of the host's byte order and
support unaligned offsets.

Offsets are unwrapped `i32` values, starting at zero. Negative offsets, missing
bytes and offsets outside the buffer return nil. Bounds are checked using
`offset <= bytes.count - width` before adding field offsets, avoiding signed
offset overflow. Reads do not modify the Bytes, advance a cursor, perform I/O,
allocate memory or change `netError()`. Callers explicitly choose each offset.
NUL bytes and high-bit bytes have their full binary meaning.

Unsigned 32-bit readers widen before combining bytes, preserving values above
2147483647. The library infers its i64 return types using existing arithmetic;
source `i64` annotations remain unsupported. Unsigned 64-bit values above
9223372036854775807 cannot fit Rut's implemented signed scalar types. There is
no unsigned 64-bit reader or silent narrowing to negative values; supporting
that full range needs a separate numeric-type design.

TCP callers must first acquire a complete field using `readExactly` or an
existing buffered protocol read. The decoders accept the returned Bytes but do
not fetch additional data. UDP callers can decode fields in a received datagram
using explicit offsets. This library does not add variable-length integer
encoding, floating point decoding, serialization or streaming parser loops.

Tests compare all ten readers against Python's `struct` codec over deterministic
random and boundary values on epoll and io_uring at optimization levels 0 and 2.
They cover truncation, empty
input, negative/extreme offsets, unaligned fields, wrong expected values, the
full unsigned 32-bit range, and native execution after removing imported source.
