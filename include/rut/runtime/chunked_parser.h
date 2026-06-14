/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

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
    u32 chunk_remaining;  // bytes left in current chunk data
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
