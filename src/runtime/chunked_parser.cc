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

#include "rut/runtime/chunked_parser.h"

namespace rut {

static i32 hex_val(u8 c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
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
                u32 avail = in_len - pos;
                u32 n = avail < chunk_remaining ? avail : chunk_remaining;
                *out_start = pos;
                *out_len = n;
                *consumed = pos + n;
                chunk_remaining -= n;
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
