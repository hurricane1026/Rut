#pragma once

#include "rut/common/types.h"

namespace rut {

// Checker-facing declarations for builtins whose runtime services are supplied
// by the control plane. Keeping these signatures in one table prevents the
// parser/analyzer, docs, and eventual runtime lowering from inventing subtly
// different contracts while that lowering is added incrementally.
enum class BuiltinDeclType : u8 {
    Void,
    Bool,
    Server,
    Stats,
    Metrics,
};

enum class BuiltinReceiver : u8 {
    None,
    Upstream,
};

enum BuiltinContext : u8 {
    BuiltinInRoute = 1u << 0,
    BuiltinInTimer = 1u << 1,
};

struct BuiltinParamDecl {
    Str label{};  // empty means positional/unlabelled
    BuiltinDeclType type = BuiltinDeclType::Void;
};

struct BuiltinDecl {
    Str name{};
    BuiltinReceiver receiver = BuiltinReceiver::None;
    BuiltinDeclType return_type = BuiltinDeclType::Void;
    u8 contexts = 0;
    bool statement_only = false;
    bool requires_pinned_timer = false;
    bool json_serializable = false;
    u8 param_count = 0;
    BuiltinParamDecl params[2]{};
};

inline constexpr BuiltinDecl kControlPlaneBuiltinDecls[] = {
    {{"stats", 5},
     BuiltinReceiver::None,
     BuiltinDeclType::Stats,
     BuiltinInRoute | BuiltinInTimer,
     false,
     false,
     true,
     0,
     {}},
    {{"metrics", 7},
     BuiltinReceiver::None,
     BuiltinDeclType::Metrics,
     BuiltinInRoute | BuiltinInTimer,
     false,
     false,
     true,
     0,
     {}},
    {{"reload", 6},
     BuiltinReceiver::None,
     BuiltinDeclType::Bool,
     BuiltinInRoute,
     false,
     false,
     false,
     0,
     {}},
    {{"mark", 4},
     BuiltinReceiver::Upstream,
     BuiltinDeclType::Bool,
     BuiltinInTimer,
     false,
     true,
     false,
     2,
     {{{}, BuiltinDeclType::Server}, {{"healthy", 7}, BuiltinDeclType::Bool}}},
};

constexpr const BuiltinDecl* find_control_plane_builtin(BuiltinReceiver receiver, Str name) {
    for (const auto& decl : kControlPlaneBuiltinDecls) {
        if (decl.receiver == receiver && decl.name.eq(name)) return &decl;
    }
    return nullptr;
}

}  // namespace rut
