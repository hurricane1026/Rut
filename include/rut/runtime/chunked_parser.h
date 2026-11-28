#pragma once

#include "rut/common/types.h"

namespace rut {

enum class ChunkStatus : u8 {
    NeedMore,  // Need more input bytes
    Data,      // Decoded data available: out_start/out_len set
    Done,      // Final 0-length chunk seen
    Error,     // Malformed chunk encoding
};

struct ChunkedParser {
    enum class State : u8 {
        Size,           // Parsing hex chunk size
        SizeLF,         // Expecting \n after \r in size line
        Extension,      // Skipping chunk extension (after ';')
        Data,           // Reading chunk data bytes
        DataCR,         // Expecting \r after chunk data
        DataLF,         // Expecting \n after \r
        Trailer,        // Start of trailer line: \r means empty line (end)
        TrailerLF,      // Expecting \n after \r at start of line (final \r\n)
        TrailerLine,    // Inside a trailer header line, skip until \r\n
        TrailerLineLF,  // Expecting \n after \r in a trailer line
        Complete,
    };

    State state;
    i64 chunk_remaining;  // bytes left in current chunk data
    bool has_digits;      // at least one hex digit seen in current size field

    void reset() {
        state = State::Size;
        chunk_remaining = 0;
        has_digits = false;
    }

    // Process input[0..in_len). Returns status.
    // On Data: sets *out_start and *out_len to the decoded body region
    //   within input[] (zero-copy). Caller forwards input[out_start..+out_len).
    // *consumed: how many input bytes were consumed (advance past this).
    // Call repeatedly until NeedMore or Done.
    ChunkStatus feed(const u8* input, u32 in_len, u32* consumed, u32* out_start, u32* out_len);
};

}  // namespace rut
