#include "rut/runtime/chunked_parser.h"

#include "rut/common/range_int.h"

namespace rut {
namespace {

using HexDigit = range_int<0, 16>;

[[nodiscard]] bool hex_digit(u8 c, HexDigit* out) {
    range_int<0, 10> digit;
    if (decltype(digit)::try_from_i64((range_int{c} - range_int<'0', '0' + 1>{}).value(), &digit)) {
        *out = digit;
        return true;
    }
    range_int<0, 6> letter;
    if (!decltype(letter)::try_from_i64((range_int{c | 0x20} - range_int<'a', 'a' + 1>{}).value(),
                                        &letter))
        return false;
    *out = letter + range_int<10, 11>{};
    return true;
}
}  // namespace

ChunkStatus ChunkedParser::feed(
    const u8* input, u32 in_len, u32* consumed, u32* out_start, u32* out_len) {
    u32 pos = 0;

    while (pos < in_len) {
        u8 c = input[pos];

        switch (state) {
            case State::Size: {
                HexDigit digit;
                if (hex_digit(c, &digit)) {
                    using Prefix = range_int<0, 0x10000000>;
                    Prefix prefix;
                    if (!Prefix::try_from_u64(chunk_remaining, &prefix)) {
                        *consumed = pos;
                        return ChunkStatus::Error;
                    }
                    chunk_remaining = (prefix.scaled_by<16>() + digit).to<u32>();
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
                const auto cursor = range_int{pos};
                const auto remaining = range_int{chunk_remaining};
                auto available = cursor;
                if (!decltype(available)::try_from_i64((range_int{in_len} - cursor).value(),
                                                       &available)) {
                    *consumed = pos;
                    return ChunkStatus::Error;
                }
                const auto taken = available.min(remaining);
                u32 next;
                u32 left;
                if (!(cursor + taken).to(&next) || !(remaining - taken).to(&left)) {
                    *consumed = pos;
                    return ChunkStatus::Error;
                }
                *out_start = pos;
                *out_len = taken.to<u32>();
                *consumed = next;
                chunk_remaining = left;
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
