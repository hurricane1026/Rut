#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/arena.h"

namespace rut {
namespace rir {

// ── Builder Error ───────────────────────────────────────────────────
// Returned by builder operations that can fail.

enum class RirError : u8 {
    OutOfMemory,   // Arena allocation failed
    InvalidState,  // e.g., emit after terminator, invalid block ID
    CapacityFull,  // Module/function capacity exceeded
};

// ── Source Location ─────────────────────────────────────────────────
// Every instruction maps back to source for --emit-rir and diagnostics.

struct SourceLoc {
    u32 line;
    u32 col;
};

// ── Type System ─────────────────────────────────────────────────────
// Mirrors Rutlang language types. Domain types are first-class so that
// RIR-level optimizations can reason about them (e.g., CIDR containment
// folding, Duration comparison strength reduction).

enum class TypeKind : u8 {
    // Primitives
    Void,
    Bool,
    I32,
    I64,
    U32,
    U64,
    F64,
    Str,

    // Domain types — first-class in the IR so optimizations can exploit
    // their semantics (e.g., constant-fold Duration comparisons).
    ByteSize,
    Duration,
    Time,
    IP,
    CIDR,
    MediaType,
    StatusCode,
    Method,
    Bytes,

    // Composite
    Optional,  // inner type follows
    Struct,    // named struct with fields
    Array,     // element type follows
};

// Type is arena-allocated and immutable once created.
// Composite types (Optional, Array) chain to their inner type.
// Struct types reference a StructDef for field layout.
struct Type {
    TypeKind kind;

    // For Optional/Array: the element type.
    const Type* inner;

    // For Struct: points to the struct definition.
    // Null for non-struct types.
    struct StructDef* struct_def;
};

// Field within a struct definition.
struct FieldDef {
    Str name;
    const Type* type;
};

// Struct definition — arena-allocated, fields stored inline after.
struct StructDef {
    Str name;
    u32 field_count;
    // FieldDef fields[] follows in arena memory (flexible array idiom).
    FieldDef* fields() { return reinterpret_cast<FieldDef*>(this + 1); }
    const FieldDef* fields() const { return reinterpret_cast<const FieldDef*>(this + 1); }
};

// ── Values (SSA) ────────────────────────────────────────────────────
// Index-based SSA: %0, %1, %2... are indices into the function's value
// table. This is cache-friendly, trivially serializable, and works
// naturally with FixedVec/Arena storage.
//
// IMPORTANT: ValueId and BlockId are function-scoped. They are bare
// indices and do NOT encode which function they belong to. Callers
// must never use a ValueId/BlockId produced by one function when
// emitting into a different function — the builder validates index
// range but cannot detect cross-function misuse by design.

struct ValueId {
    u32 id;

    bool operator==(ValueId other) const { return id == other.id; }
    bool operator!=(ValueId other) const { return id != other.id; }
};

// Sentinel for "no value" (void-returning instructions).
static constexpr ValueId kNoValue = {0xFFFFFFFF};

// ── Block IDs ───────────────────────────────────────────────────────

struct BlockId {
    u32 id;

    bool operator==(BlockId other) const { return id == other.id; }
    bool operator!=(BlockId other) const { return id != other.id; }
};

// Sentinel for "no block" (invalid block ID).
static constexpr BlockId kNoBlock = {0xFFFFFFFF};

// A produced SSA value: the result of an instruction.
struct Value {
    const Type* type;
    BlockId def_block;  // block containing the defining instruction
    u32 def_inst;       // index of the defining instruction within the block
};

// ── Opcodes ─────────────────────────────────────────────────────────
// Flat enumeration of all RIR operations. Grouped by category.
// The opcode determines operand layout (see Instruction).

enum class Opcode : u8 {
    // ── Constants ──
    ConstStr,       // %r = const.str "literal"
    ConstI32,       // %r = const.i32 42
    ConstI64,       // %r = const.i64 42
    ConstBool,      // %r = const.bool true
    ConstDuration,  // %r = const.duration <seconds>  (printed as raw i64)
    ConstByteSize,  // %r = const.bytesize <bytes>   (printed as raw i64)
    ConstMethod,    // %r = const.method <code>       (printed as raw u8)
    ConstStatus,    // %r = const.status <code>       (printed as raw i32)

    // ── Request access ──
    ReqHeader,          // %r = req.header "Name"        → Optional(str)
    ReqParam,           // %r = req.param "id"           → str
    ReqMethod,          // %r = req.method               → Method
    ReqPath,            // %r = req.path                 → str
    ResumeEventKind,    // %r = ctx.resume_event_kind    → i32
    ResumeEventResult,  // %r = ctx.resume_event_result → i32
    CtxLoadSlotI32,     // %r = ctx.slot[i]            → i32
                        // Falls back to current resume metadata when
                        // slot data is unavailable: even index slots
                        // read resume_event_kind, odd index slots read
                        // resume_event_result.
    ReqRemoteAddr,      // %r = req.remote_addr          → IP
    ReqContentLength,   // %r = req.content_length       → ByteSize
    ReqCookie,          // %r = req.cookie "name"        → Optional(str)

    // ── Request mutation ──
    ReqSetHeader,     // req.set_header "Name", %val
    ReqSetPath,       // req.set_path %path
    CtxStoreSlotI32,  // ctx.slot[i] = %val (stored as zero-extended i64 slot)

    // ── String operations ──
    StrHasPrefix,    // %r = str.has_prefix %s, %pfx    → bool
    StrTrimPrefix,   // %r = str.trim_prefix %s, %pfx   → str
    StrRegexMatch,   // %r = str.regex_match %s, "re"   → bool
    StrInterpolate,  // %r = str.interpolate [%a, %b..]  → str (variadic)

    // ── Comparisons ──
    CmpEq,  // %r = cmp.eq %a, %b  → bool
    CmpNe,  // %r = cmp.ne %a, %b  → bool
    CmpLt,  // %r = cmp.lt %a, %b  → bool
    CmpGt,  // %r = cmp.gt %a, %b  → bool
    CmpLe,  // %r = cmp.le %a, %b  → bool
    CmpGe,  // %r = cmp.ge %a, %b  → bool

    // ── Domain operations ──
    TimeNow,         // %r = time.now               → Time
    TimeDiff,        // %r = time.diff %a, %b       → Duration
    IpInCidr,        // %r = ip.in_cidr %ip, cidr   → bool
    HashHmacSha256,  // %r = hash.hmac_sha256 %k,%d → Bytes
    BytesHex,        // %r = bytes.hex %b            → str

    // ── Counter ──
    CounterIncr,  // %r = counter.incr %key, window → i32

    // ── Struct operations ──
    StructField,   // %r = struct.field %s, "name"  → T
    StructCreate,  // %r = struct.create Name {...}  → Struct
    BodyParse,     // %r = body.parse TypeName       → T
    ArrayLen,      // %r = array.len %arr            → i32
    ArrayGet,      // %r = array.get %arr, %idx      → T

    // ── Optional operations ──
    OptNil,     // %r = opt.nil                    → Optional(T)
    OptWrap,    // %r = opt.wrap %v               → Optional(T)
    OptIsNil,   // %r = opt.is_nil %v              → bool
    OptUnwrap,  // %r = opt.unwrap %v              → inner type

    // ── Value selection ──
    Select,  // %r = select %cond, %then, %else  → T

    // ── Instrumentation (compiler-inserted) ──
    TraceFuncEnter,
    TraceFuncExit,
    TraceIoStart,
    TraceIoEnd,
    MetricHistRecord,
    MetricCounterIncr,
    AccessLogWrite,

    // ── Terminators ── (must be last instruction in a block)
    Br,          // br %cond, then_block, else_block
    Jmp,         // jmp target_block
    RetStatus,   // ret.status — two encodings, disambiguated by operand_count:
                 //   operand_count == 0 (literal form): imm.i64_val holds
                 //     a packed (status | body_idx<<16 | headers_idx<<32):
                 //       bits [ 0:16): HTTP status code (0..65535)
                 //       bits [16:32): 1-based response_bodies index,
                 //                     0 = no custom body
                 //       bits [32:48): 1-based response header_sets index,
                 //                     0 = no custom headers
                 //       bits [48:64): reserved (must be 0)
                 //   operand_count >  0 (value form):   operands[0] is an
                 //     SSA i32 status code; imm is unused and both
                 //     body_idx and headers_idx are implicitly 0.
                 //   Printers/decoders MUST branch on operand_count before
                 //   reading imm.i64_val — doing otherwise will print
                 //   garbage for the value form and miss body/header idx
                 //   in the literal form.
    RetForward,  // ret.forward upstream [, options]

    // ── Yield (I/O suspend → state machine boundary) ──
    YieldTimer,     // yield.timer ms, next_state
    YieldHttpGet,   // %r = yield.http_get url, headers
    YieldHttpPost,  // %r = yield.http_post url, headers, body
    YieldForward,   // %r = yield.forward upstream
};

// ── Instruction ─────────────────────────────────────────────────────
// Tagged union with inline storage for up to 3 operands (covers ~95%
// of instructions). Variadic ops (str.interpolate, struct.create)
// use arena-allocated operand arrays.

static constexpr u32 kMaxInlineOperands = 3;

struct Instruction {
    Opcode op;
    ValueId result;  // produced value (kNoValue for void ops)
    SourceLoc loc;

    // Inline operand storage: most instructions use 1-3 operands.
    u32 operand_count;
    ValueId operands[kMaxInlineOperands];

    // Overflow for variadic instructions (arena-allocated).
    // Non-null only when operand_count > kMaxInlineOperands.
    ValueId* extra_operands;

    // Instruction-specific immediate data (tagged by opcode).
    union Immediate {
        Str str_val;               // ConstStr, ReqHeader, ReqParam, ReqCookie, etc.
        i32 i32_val;               // ConstI32, ConstStatus.
        i64 i64_val;               // ConstI64, ConstDuration, ConstByteSize;
                                   // RetStatus literal form packs
                                   // (status | body_idx<<16 | headers_idx<<32)
                                   // — decode before display (see RetStatus
                                   // opcode comment).
        bool bool_val;             // ConstBool
        u8 method_val;             // ConstMethod (HTTP method enum)
        BlockId block_targets[2];  // Br: [then, else]; Jmp: [target, _]
        struct {
            Str name;
            const Type* type;
        } struct_ref;  // StructCreate, BodyParse, StructField
    } imm;

    // Access operand by index, handling inline vs overflow.
    ValueId operand(u32 i) const {
        if (i < kMaxInlineOperands) return operands[i];
        return extra_operands[i - kMaxInlineOperands];
    }

    // Is this a yield (I/O suspend point → state machine boundary)?
    // Yields are a subset of terminators — no instructions may follow
    // within the same block. Yield instructions produce SSA values
    // (the I/O result); the state machine construction pass (Pass 3)
    // splits the function at yield boundaries and wires the result
    // value into the continuation block's live-in set.
    // Note: DESIGN.md shows nil checks as `%v.is_nil` (sugar), but this
    // IR uses an explicit `OptIsNil` opcode for uniformity.
    bool is_yield() const {
        switch (op) {
            case Opcode::YieldHttpGet:
            case Opcode::YieldHttpPost:
            case Opcode::YieldForward:
            case Opcode::YieldTimer:
                return true;
            default:
                return false;
        }
    }

    // Is this a block-ending instruction? Uses explicit switch rather
    // than range check so opcode reordering can't silently break semantics.
    bool is_terminator() const {
        switch (op) {
            case Opcode::Br:
            case Opcode::Jmp:
            case Opcode::RetStatus:
            case Opcode::RetForward:
                return true;
            default:
                return is_yield();
        }
    }
};

// ── Block ───────────────────────────────────────────────────────────
// Basic block: a sequence of instructions ending with exactly one
// terminator. Instructions are arena-allocated as a contiguous array.

struct Block {
    BlockId id;
    Str label;  // human-readable name for --emit-rir

    // Instructions stored as arena-allocated array.
    Instruction* insts;
    u32 inst_count;
    u32 inst_cap;

    // Returns the terminator if the block is properly terminated, nullptr otherwise.
    const Instruction* terminator() const {
        if (inst_count == 0) return nullptr;
        const Instruction* last = &insts[inst_count - 1];
        return last->is_terminator() ? last : nullptr;
    }
};

// ── Function ────────────────────────────────────────────────────────
// One function per route handler (after full inlining).
// Contains the entry block and all reachable blocks.

struct Function {
    Str name;  // e.g., "handle_get_users_id"

    // Route metadata.
    Str route_pattern;  // e.g., "/users/:id"
    u8 http_method;     // route method key (0 = any, 1..9 = full HTTP method)

    // Blocks: arena-allocated array. blocks[0] is always entry.
    Block* blocks;
    u32 block_count;
    u32 block_cap;

    // SSA value table: all values produced by instructions.
    Value* values;
    u32 value_count;
    u32 value_cap;

    // Yield point count (determines state machine states).
    u32 yield_count;
    bool state_zero_enters_entry;
    u32 resume_terminal_block;
    bool has_explicit_resume_blocks;
    static constexpr u32 kMaxResumeBlocks = 8;
    u32 resume_blocks[kMaxResumeBlocks];

    // Per-yield ABI metadata. yield_payload[i] is the u32 payload carried
    // by state i+1, and yield_kinds[i] is the jit::YieldKind ABI byte.
    // Both arrays are arena-allocated with length = yield_count.
    u32* yield_payload;
    u8* yield_kinds;

    Block* entry() { return block_count > 0 ? &blocks[0] : nullptr; }
    const Block* entry() const { return block_count > 0 ? &blocks[0] : nullptr; }
};

// ── Module ──────────────────────────────────────────────────────────
// Top-level container: all route handler functions from one .rut file.

struct Module {
    Str name;  // source file name

    // Struct type definitions (shared across functions).
    StructDef** struct_defs;
    u32 struct_count;
    u32 struct_cap;

    // Functions (one per route handler).
    Function* functions;
    u32 func_count;
    u32 func_cap;

    // Response-body literals collected from RetStatus terminators.
    // The array is 0-based, but the emit_ret_status body_idx and the
    // handler ABI use 1-based indices (0 reserved as "no custom
    // body"), so `body_idx = i + 1` maps to `response_bodies[i]`.
    // Identical literals are deduplicated during lowering so the
    // table stays small. Populated at lower_to_rir time; the table is
    // then consumed by whatever populates RouteConfig (tests / future
    // compile→config helper) — codegen itself only packs the index
    // into the handler's return value, it doesn't read the bytes.
    static constexpr u32 kMaxResponseBodies = 128;
    Str response_bodies[kMaxResponseBodies];
    u32 response_body_count = 0;

    // Response header sets collected from RetStatus terminators. Shape
    // is the flat-pool design (decision B2): all (key, value) pairs
    // across the module live in header_keys[] / header_values[]; each
    // set is a (offset, count) slice into those arrays. Entries are
    // deduplicated by full (ordered) pair-sequence equality during
    // lowering. Indexed 1-based from the handler ABI (0 = no custom
    // headers), so `headers_idx = i + 1` maps to `header_sets[i]`.
    struct HeaderSetRef {
        u16 offset;  // into header_keys / header_values
        u16 count;
    };
    static constexpr u32 kMaxHeaderSets = 128;
    static constexpr u32 kMaxHeaderPoolEntries = 512;
    Str header_keys[kMaxHeaderPoolEntries];
    Str header_values[kMaxHeaderPoolEntries];
    u32 header_pool_used = 0;
    HeaderSetRef header_sets[kMaxHeaderSets];
    u32 header_set_count = 0;

    // Upstream declarations carried verbatim from the DSL so a
    // compile→config helper can translate them into
    // RouteConfig::add_upstream calls without re-parsing addresses.
    // has_address == false means the DSL declared the name only; the
    // runtime must bind it separately. ip is host byte order.
    struct Upstream {
        Str name;
        bool has_address;
        u32 ip;
        u16 port;
    };
    static constexpr u32 kMaxUpstreams = 32;
    Upstream upstreams[kMaxUpstreams];
    u32 upstream_count = 0;

    // Arena that owns all IR memory (mmap-backed, compiler use).
    MmapArena* arena;
};

}  // namespace rir
}  // namespace rut
