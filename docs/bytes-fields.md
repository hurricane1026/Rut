# Bytes field extraction

Bytes provides two built-in methods for extracting protocol fields without text
conversion, an import, a new keyword or an external dependency:

| Method | Result | Contract |
| --- | --- | --- |
| `data.slice(start, end)` | `Bytes?` | Checked half-open byte range `[start, end)`. |
| `data.find(delimiter)` | `i32?` | First exact occurrence of delimiter, starting at byte zero. |
| `data.find(delimiter, start)` | `i32?` | First exact occurrence at or after start; result is an absolute offset in data. |

Receivers and delimiters must be unwrapped Bytes. Bounds and search starts must
be unwrapped i32 values. Arguments are evaluated once in source order, receiver
first. These are methods of Rut's custom Bytes type, not Swift String or Array
collection APIs. No range syntax or implicit Bytes/str coercion is added.

## Bounds and empty values

Slice succeeds only when `0 <= start <= end <= data.count`. Negative, reversed
or out-of-range bounds return nil; they are never clamped or interpreted from
the end. Equal bounds produce a **present empty Bytes**, including
`data.slice(data.count, data.count)` and `b"".slice(0, 0)`.

Find accepts `0 <= start <= data.count`. Missing delimiters and invalid starts
return nil. An empty delimiter matches at start, including the end of the input.
A match at byte zero is a present zero, not failure. Search considers complete
matches only; NUL and non-UTF-8 octets have their ordinary binary meaning. Search
after an earlier match by passing an explicit new start; overlapping matches are
not skipped automatically. Delimiters may themselves be dynamic Bytes slices.

## Protocol fields

`readLine` retains CRLF and `parseInt` requires the entire input to be decimal.
Find the delimiter and slice out the field before parsing:

```rut
func lengthField(_ line: Bytes) -> i32 {
    guard line[0].or(-1) == 36 else { nil } // '$'
    guard let end = line.find(b"\r\n") else { nil }
    guard let digits = line.slice(1, end) else { nil }
    parseInt(digits)
}
```

This helper only extracts a RESP-style length field; the protocol library must
separately validate allowed lengths, frame completeness and trailing bytes.
Generic transport operations do not interpret application framing.

See [the executable field example](../examples/bytes-fields.rut),
[integer parsing](parse-integers.md), [binary integer reads](binary-integers.md)
and [TCP/UDP clients](net-clients.md).

## Storage and execution

Slice returns an immutable, non-owning view into the input storage: it does not
copy or allocate. It retains the input's lifetime and does not permit mutation or
escape into a later request or WebSocket callback. Ordinary outbound continuation
storage retains live byte values across suspension; a field extracted from one
TCP read remains valid after a later read. HTTP request-body and WebSocket views
retain their existing buffering and callback lifetime restrictions.

Find allocates no storage and reuses the runtime's existing bounded `memmem`
search, also used by String contains. It searches only the supplied byte span;
input need not be NUL-terminated or padded. Neither method performs I/O, advances
a connection cursor or changes `netError()`. JIT and native programs share the
same bounds and optional-value semantics. The compiler verifies exact intrinsic
operand/result shapes before generating LLVM code.

Tests cover both I/O backends at optimization levels 0 and 2, independent Python
slice/find oracles, binary/empty/boundary inputs, decimal field composition,
source removal, native-loaded HTTP/WebSocket handlers, protected-page search
boundaries and a field retained across another TCP read.
