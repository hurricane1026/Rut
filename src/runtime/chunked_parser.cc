#include "rut/runtime/chunked_parser.h"

namespace rut {

static i32 hex_val(u8 c) {
    if (c >= '0' && c <= '9') return static_cast<i32>(c) - '0';
    if (c >= 'a' && c <= 'f') return 10 + (static_cast<i32>(c) - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (static_cast<i32>(c) - 'A');
    return -1;
}

ChunkStatus ChunkedParser::feed(
    const u8* input, u32 in_len, u32* consumed, u32* out_start, u32* out_len) {
    u32 pos = 0;

    while (pos < in_len) {
        u8 c = input[pos];

        switch (state) {
            case State::Size: {
                i32 v = hex_val(c);
                if (v >= 0) {
                    if (chunk_remaining > 0x0FFFFFFFu) {
                        *consumed = pos;
                        return ChunkStatus::Error;
                    }
                    chunk_remaining = (chunk_remaining << 4) | static_cast<u32>(v);
                    has_digits = true;
                    pos++;
                } else if (c == '\r') {
                    if (!has_digits) {
                        *consumed = pos;
                        return ChunkStatus::Error;
                    }
                    state = State::SizeLF;
                    pos++;
                } else if (c == ';') {
                    if (!has_digits) {
                        *consumed = pos;
                        return ChunkStatus::Error;
                    }
                    state = State::Extension;
                    pos++;
                } else {
                    *consumed = pos;
                    return ChunkStatus::Error;
                }
                break;
            }

            case State::SizeLF: {
                if (c != '\n') {
                    *consumed = pos;
                    return ChunkStatus::Error;
                }
                pos++;
                if (chunk_remaining == 0) {
                    state = State::Trailer;
                } else {
                    state = State::Data;
                }
                break;
            }

            case State::Extension: {
                if (c == '\r') {
                    state = State::SizeLF;
                }
                pos++;
                break;
            }

            case State::Data: {
                // Bulk copy: consume min(remaining input, chunk_remaining).
                u32 avail = static_cast<u32>(static_cast<i64>(in_len) - static_cast<i64>(pos));
                u32 n = avail < chunk_remaining ? avail : chunk_remaining;
                *out_start = pos;
                *out_len = n;
                *consumed = static_cast<u32>(static_cast<i64>(pos) + static_cast<i64>(n));
                chunk_remaining =
                    static_cast<u32>(static_cast<i64>(chunk_remaining) - static_cast<i64>(n));
                if (chunk_remaining == 0) {
                    state = State::DataCR;
                }
                return ChunkStatus::Data;
            }

            case State::DataCR: {
                if (c != '\r') {
                    *consumed = pos;
                    return ChunkStatus::Error;
                }
                state = State::DataLF;
                pos++;
                break;
            }

            case State::DataLF: {
                if (c != '\n') {
                    *consumed = pos;
                    return ChunkStatus::Error;
                }
                state = State::Size;
                chunk_remaining = 0;
                has_digits = false;
                pos++;
                break;
            }

            case State::Trailer: {
                if (c == '\r') {
                    state = State::TrailerLF;
                    pos++;
                    break;
                }
                // Non-\r: start of a trailer header line.
                state = State::TrailerLine;
                pos++;
                break;
            }

            case State::TrailerLF: {
                if (c != '\n') {
                    *consumed = pos;
                    return ChunkStatus::Error;
                }
                pos++;
                state = State::Complete;
                *consumed = pos;
                return ChunkStatus::Done;
            }

            case State::TrailerLine: {
                if (c == '\r') {
                    state = State::TrailerLineLF;
                }
                pos++;
                break;
            }

            case State::TrailerLineLF: {
                if (c != '\n') {
                    *consumed = pos;
                    return ChunkStatus::Error;
                }
                // End of this trailer line, go back to check for more.
                state = State::Trailer;
                pos++;
                break;
            }

            case State::Complete: {
                *consumed = pos;
                return ChunkStatus::Done;
            }
        }
    }

    *consumed = pos;
    return ChunkStatus::NeedMore;
}

}  // namespace rut
