// Check native integer conversions after Clang resolves aliases and promotions.
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Analysis/CFG.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/DenseMap.h"

using namespace clang;

namespace {
const VarDecl* variable(const Expr* expr) {
    const auto* ref = dyn_cast<DeclRefExpr>(expr->IgnoreParenImpCasts());
    return ref ? dyn_cast<VarDecl>(ref->getDecl()) : nullptr;
}

bool fits_i64(ASTContext& context, const Expr* expr, bool allow_first_out_of_range = false) {
    if (const auto value = expr->getIntegerConstantExpr(context)) {
        return !value->isNegative() &&
               (value->getActiveBits() < 64 ||
                (allow_first_out_of_range && value->getActiveBits() == 64 && value->isPowerOf2()));
    }
    // Usual arithmetic conversions promote a narrow unsigned loop bound to u64.
    // Stripping an implicit conversion from a signed bound would lose negatives.
    expr = expr->IgnoreParens();
    while (expr->getType()->isUnsignedIntegerType()) {
        if (context.getIntWidth(expr->getType()) < 64) return true;
        const auto* cast = dyn_cast<ImplicitCastExpr>(expr);
        if (!cast) break;
        expr = cast->getSubExpr()->IgnoreParens();
    }
    return false;
}

const FunctionDecl* enclosing_function(ASTContext& context, const Stmt& stmt) {
    auto node = DynTypedNode::create(stmt);
    while (true) {
        const auto parents = context.getParents(node);
        if (parents.size() != 1) return nullptr;
        node = parents[0];
        if (const auto* function = node.get<FunctionDecl>()) return function;
    }
}

// Keep the proof local. A reference, capture, or address escape could change a
// counter without a visible assignment. Nested writes can have unspecified
// evaluation order relative to the cast, so only standalone writes are tracked.
class LocalReads : public RecursiveASTVisitor<LocalReads> {
    ASTContext& context;
    const VarDecl* cursor;

public:
    LocalReads(ASTContext& context, const VarDecl* cursor) : context(context), cursor(cursor) {}

    bool VisitLambdaExpr(LambdaExpr* lambda) {
        for (const LambdaCapture& capture : lambda->captures())
            if (capture.capturesVariable() && capture.getCapturedVar() == cursor) return false;
        return true;
    }

    bool VisitDeclRefExpr(DeclRefExpr* ref) {
        if (ref->getDecl() != cursor) return true;
        const Stmt* operand = ref;
        auto parents = context.getParents(*operand);
        while (parents.size() == 1) {
            const auto* cast = parents[0].get<ImplicitCastExpr>();
            if (!parents[0].get<ParenExpr>() && (!cast || cast->getCastKind() != CK_NoOp)) break;
            operand = parents[0].get<Expr>();
            parents = context.getParents(*operand);
        }
        if (parents.size() != 1) return false;
        const auto* parent = parents[0].get<Expr>();
        if (const auto* cast = dyn_cast_or_null<ImplicitCastExpr>(parent))
            return cast->getCastKind() == CK_LValueToRValue;
        if (const auto* op = dyn_cast_or_null<UnaryOperator>(parent);
            op && op->isIncrementDecrementOp())
            return standalone_write(*op);
        if (const auto* op = dyn_cast_or_null<BinaryOperator>(parent);
            op && op->isAssignmentOp() && op->getLHS() == operand)
            return standalone_write(*op);
        return false;
    }

private:
    bool standalone_write(const Expr& expr) {
        const auto parents = context.getParents(expr);
        if (parents.size() != 1) return false;
        if (parents[0].get<CompoundStmt>()) return true;
        if (const auto* loop = parents[0].get<ForStmt>()) return loop->getInc() == &expr;
        return false;
    }
};

bool proves_bound(ASTContext& context, const Expr* condition, const VarDecl* cursor, bool taken) {
    if (!condition) return false;
    condition = condition->IgnoreParenImpCasts();
    if (const auto* op = dyn_cast<UnaryOperator>(condition); op && op->getOpcode() == UO_LNot)
        return proves_bound(context, op->getSubExpr(), cursor, !taken);
    const auto* comparison = dyn_cast<BinaryOperator>(condition);
    if (!comparison) return false;
    auto op = comparison->getOpcode();
    const Expr* lhs = comparison->getLHS();
    const Expr* rhs = comparison->getRHS();
    if ((op == BO_LAnd && taken) || (op == BO_LOr && !taken))
        return proves_bound(context, lhs, cursor, taken) ||
               proves_bound(context, rhs, cursor, taken);
    if (!comparison->isComparisonOp() || op == BO_Cmp) return false;
    if (variable(lhs) != cursor) {
        if (variable(rhs) != cursor) return false;
        op = BinaryOperator::reverseComparisonOp(op);
        rhs = lhs;
    }
    if (!taken) op = BinaryOperator::negateComparisonOp(op);
    return (op == BO_LT || op == BO_LE || op == BO_EQ) && fits_i64(context, rhs, op == BO_LT);
}

class SignedConversionVisitor : public RecursiveASTVisitor<SignedConversionVisitor> {
    ASTContext& context;
    const FunctionDecl* cached_function = nullptr;
    std::unique_ptr<CFG> graph;
    llvm::DenseMap<const VarDecl*, bool> eligible;

public:
    explicit SignedConversionVisitor(ASTContext& context) : context(context) {}

    bool shouldVisitTemplateInstantiations() const { return true; }

    bool VisitCastExpr(CastExpr* cast) {
        if (cast->getCastKind() != CK_IntegralCast) return true;
        const Expr* input = cast->getSubExpr();
        const QualType source = input->getType();
        const QualType target = cast->getType();
        if (!source->isUnsignedIntegerType() || !target->isSignedIntegerType() ||
            context.getIntWidth(source) != 64 || context.getIntWidth(target) != 64 ||
            context.getSourceManager().isInSystemHeader(cast->getExprLoc()))
            return true;
        if (fits_i64(context, input) || prove_local_cast(*cast)) return true;
        auto& diagnostics = context.getDiagnostics();
        const auto id = diagnostics.getCustomDiagID(DiagnosticsEngine::Warning,
                                                    "u64 to i64 conversion requires a range proof");
        diagnostics.Report(cast->getExprLoc(), id) << cast->getSourceRange();
        return true;
    }

private:
    bool prove_local_cast(const CastExpr& cast) {
        const auto* cursor = variable(cast.getSubExpr());
        if (!cursor || !cursor->hasLocalStorage() || cursor->getType()->isReferenceType() ||
            cursor->getType().isVolatileQualified())
            return false;
        const auto* function = enclosing_function(context, cast);
        if (!function || !function->hasBody()) return false;
        if (function != cached_function) {
            cached_function = function;
            eligible.clear();
            graph.reset();
        }
        const auto [entry, inserted] = eligible.try_emplace(cursor, false);
        if (inserted) entry->second = LocalReads(context, cursor).TraverseStmt(function->getBody());
        if (!entry->second) return false;
        if (!graph) {
            CFG::BuildOptions options;
            options.setAlwaysAdd(Stmt::ImplicitCastExprClass);
            options.setAlwaysAdd(Stmt::CXXStaticCastExprClass);
            options.setAlwaysAdd(Stmt::CStyleCastExprClass);
            options.setAlwaysAdd(Stmt::CXXFunctionalCastExprClass);
            options.setAlwaysAdd(Stmt::BinaryOperatorClass);
            options.setAlwaysAdd(Stmt::CompoundAssignOperatorClass);
            options.setAlwaysAdd(Stmt::UnaryOperatorClass);
            options.setAlwaysAdd(Stmt::DeclStmtClass);
            graph = CFG::buildCFG(function, function->getBody(), &context, options);
        }
        if (!graph) return false;
        struct State {
            const CFGBlock* block;
            bool bounded;
        };
        llvm::SmallVector<State, 16> work;
        // Explore guarded and unguarded paths independently at every join.
        // A write invalidates the fact until a later branch establishes it again.
        llvm::BitVector visited[2] = {llvm::BitVector(graph->size()),
                                      llvm::BitVector(graph->size())};
        auto enqueue = [&](const CFGBlock* block, bool bounded) {
            const auto id = block->getBlockID();
            if (visited[bounded].test(id)) return;
            visited[bounded].set(id);
            work.push_back({block, bounded});
        };
        enqueue(&graph->getEntry(), false);
        bool found = false;
        while (!work.empty()) {
            auto [block, bounded] = work.pop_back_val();
            for (const auto& element : *block) {
                const auto stmt = element.getAs<CFGStmt>();
                if (!stmt) continue;
                const Stmt* node = stmt->getStmt();
                if (node == &cast) {
                    if (!bounded) return false;
                    found = true;
                }
                if (const auto* decl = dyn_cast<DeclStmt>(node))
                    for (const auto* local : decl->decls())
                        if (local == cursor) bounded = false;
                if (const auto* op = dyn_cast<BinaryOperator>(node);
                    op && op->isAssignmentOp() && variable(op->getLHS()) == cursor)
                    bounded = false;
                if (const auto* op = dyn_cast<UnaryOperator>(node);
                    op && op->isIncrementDecrementOp() && variable(op->getSubExpr()) == cursor)
                    bounded = false;
            }
            const Stmt* terminator = block->getTerminatorStmt();
            const auto* logical = dyn_cast_or_null<BinaryOperator>(terminator);
            const bool branch = block->succ_size() == 2 &&
                                (isa_and_nonnull<IfStmt, ForStmt, WhileStmt, DoStmt>(terminator) ||
                                 (logical && logical->isLogicalOp()));
            unsigned edge = 0;
            for (const auto& successor : block->succs()) {
                if (const auto* next = successor.getReachableBlock()) {
                    const bool proof =
                        branch &&
                        proves_bound(context, block->getLastCondition(), cursor, edge == 0);
                    enqueue(next, bounded || proof);
                }
                ++edge;
            }
        }
        return found;
    }
};

class SignedConversionConsumer : public ASTConsumer {
    void HandleTranslationUnit(ASTContext& context) override {
        SignedConversionVisitor(context).TraverseDecl(context.getTranslationUnitDecl());
    }
};

class SignedConversionAction : public PluginASTAction {
    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance&, llvm::StringRef) override {
        return std::make_unique<SignedConversionConsumer>();
    }

    bool ParseArgs(const CompilerInstance&, const std::vector<std::string>&) override {
        return true;
    }
};
}  // namespace

static FrontendPluginRegistry::Add<SignedConversionAction> registration(
    "rut-u64-to-i64",
    "Require range proofs for conversions from unsigned to signed 64-bit integers");
