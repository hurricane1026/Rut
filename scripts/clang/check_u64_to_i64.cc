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
        if (const auto* op = dyn_cast<BinaryOperator>(expr); op && op->getOpcode() == BO_Rem) {
            // A constant unsigned divisor at most 2^63 bounds every remainder to i64.
            const auto divisor = op->getRHS()->getIntegerConstantExpr(context);
            return divisor && !divisor->isZero() && !divisor->isNegative() &&
                   (divisor->getActiveBits() < 64 ||
                    (divisor->getActiveBits() == 64 && divisor->isPowerOf2()));
        }
        if (const auto* op = dyn_cast<BinaryOperator>(expr);
            op && op->getOpcode() == BO_Div && context.getIntWidth(expr->getType()) == 64) {
            const auto divisor = op->getRHS()->getIntegerConstantExpr(context);
            // UINT64_MAX / 2 == INT64_MAX.
            return divisor && !divisor->isNegative() && divisor->getActiveBits() >= 2;
        }
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
    bool allow_writes;

public:
    LocalReads(ASTContext& context, const VarDecl* cursor, bool allow_writes = true)
        : context(context), cursor(cursor), allow_writes(allow_writes) {}

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
        if (!allow_writes) return false;
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
        // The visitor checks template instantiations after their values are known.
        if (input->isValueDependent()) return true;
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
class OverflowResultVisitor : public RecursiveASTVisitor<OverflowResultVisitor> {
    ASTContext& context;
    const FunctionDecl* function = nullptr;

public:
    explicit OverflowResultVisitor(ASTContext& context) : context(context) {}

    bool shouldVisitTemplateInstantiations() const { return true; }

    bool TraverseFunctionDecl(FunctionDecl* decl) {
        return traverse_function(decl,
                                 [&] { return RecursiveASTVisitor::TraverseFunctionDecl(decl); });
    }

    bool TraverseCXXMethodDecl(CXXMethodDecl* decl) {
        return traverse_function(decl,
                                 [&] { return RecursiveASTVisitor::TraverseCXXMethodDecl(decl); });
    }

    bool TraverseLambdaExpr(LambdaExpr* lambda) {
        return traverse_function(lambda->getCallOperator(),
                                 [&] { return RecursiveASTVisitor::TraverseLambdaExpr(lambda); });
    }

    bool VisitCallExpr(CallExpr* call) {
        const auto* callee = call->getDirectCallee();
        if (!callee || !callee->getIdentifier() ||
            context.getSourceManager().isInSystemHeader(call->getExprLoc()))
            return true;
        const auto name = callee->getName();
        const auto namespace_decl =
            dyn_cast<NamespaceDecl>(callee->getDeclContext()->getRedeclContext());
        if (!namespace_decl || namespace_decl->getName() != "rut" ||
            (name != "add_overflow" && name != "sub_overflow" && name != "mul_overflow"))
            return true;
        if (function && function->hasAttr<WarnUnusedResultAttr>() && returns_status(*call))
            return true;
        auto& diagnostics = context.getDiagnostics();
        const auto id = diagnostics.getCustomDiagID(
            DiagnosticsEngine::Warning,
            "checked arithmetic requires an explicit return from a nodiscard function");
        diagnostics.Report(call->getExprLoc(), id) << call->getSourceRange();
        return true;
    }

private:
    template <typename Traverse>
    bool traverse_function(const FunctionDecl* decl, Traverse traverse) {
        const auto* previous = function;
        function = decl;
        const bool ok = traverse();
        function = previous;
        return ok;
    }

    static const ReturnStmt* exit_return(const Stmt* branch) {
        if (const auto* block = dyn_cast_or_null<CompoundStmt>(branch)) {
            if (block->body_empty()) return nullptr;
            branch = block->body_back();
            for (const auto* statement : block->body())
                if (statement != branch && !isa<Expr, DeclStmt>(statement)) return nullptr;
        }
        return dyn_cast_or_null<ReturnStmt>(branch);
    }

    bool returns_status(const CallExpr& call) {
        // Follow the truth value determined by the overflow flag. In a
        // short-circuit guard, only expressions forced by that flag qualify.
        const Stmt* expression = &call;
        bool overflow_value = true;
        while (true) {
            const auto parents = context.getParents(*expression);
            if (parents.size() != 1) return false;
            const auto& parent = parents[0];
            if (const auto* branch = parent.get<IfStmt>()) {
                if (branch->getCond() != expression) return false;
                const auto* result =
                    exit_return(overflow_value ? branch->getThen() : branch->getElse());
                if (!result || !result->getRetValue()) return false;
                if (function->getReturnType()->isBooleanType()) {
                    bool value;
                    if (result->getRetValue()->EvaluateAsBooleanCondition(value, context))
                        return !value;
                }
                return true;
            }
            if (const auto* result = parent.get<ReturnStmt>())
                return result->getRetValue() == expression &&
                       function->getReturnType()->isBooleanType();
            if (const auto* op = parent.get<UnaryOperator>()) {
                if (op->getOpcode() != UO_LNot) return false;
                overflow_value = !overflow_value;
            } else if (const auto* op = parent.get<BinaryOperator>()) {
                if (op->getOpcode() != (overflow_value ? BO_LOr : BO_LAnd)) return false;
            } else if (!parent.get<ParenExpr>() && !parent.get<ImplicitCastExpr>()) {
                return false;
            }
            expression = parent.get<Stmt>();
        }
    }
};

class OverflowResultConsumer : public ASTConsumer {
    void HandleTranslationUnit(ASTContext& context) override {
        OverflowResultVisitor(context).TraverseDecl(context.getTranslationUnitDecl());
    }
};

class OverflowResultAction : public PluginASTAction {
    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance&, llvm::StringRef) override {
        return std::make_unique<OverflowResultConsumer>();
    }

    bool ParseArgs(const CompilerInstance&, const std::vector<std::string>&) override {
        return true;
    }
};

// Widen enough to represent the exact product of any two native 128-bit
// integers. Use signed comparisons even for original unsigned operands.
class IntegerArithmeticVisitor : public RecursiveASTVisitor<IntegerArithmeticVisitor> {
    using Int = llvm::APInt;
    struct Range {
        Int min, max;
    };
    static constexpr unsigned Width = 257;
    ASTContext& context;

    Range type_range(QualType type) const {
        const auto width = context.getIntWidth(type);
        if (type->isUnsignedIntegerOrEnumerationType())
            return {Int(Width, 0), Int::getMaxValue(width).zext(Width)};
        return {Int::getSignedMinValue(width).sext(Width),
                Int::getSignedMaxValue(width).sext(Width)};
    }

    static bool fits(const Range& value, const Range& type) {
        return value.min.sge(type.min) && value.max.sle(type.max);
    }

    static bool arithmetic(BinaryOperatorKind kind) {
        return kind == BO_Add || kind == BO_Sub || kind == BO_Mul;
    }

    static Range calculate(BinaryOperatorKind kind, const Range& a, const Range& b) {
        if (kind == BO_Add || kind == BO_AddAssign) return {a.min + b.min, a.max + b.max};
        if (kind == BO_Sub || kind == BO_SubAssign) return {a.min - b.max, a.max - b.min};
        return product(a, b);
    }

    Range expr_range(const Expr* expr, QualType type, unsigned depth = 0) const {
        const auto limits = type_range(type);
        if (depth == 12) return limits;
        expr = expr->IgnoreParens();
        if (auto value = expr->getIntegerConstantExpr(context)) {
            const Int exact = value->extend(Width);
            if (fits({exact, exact}, limits)) return {exact, exact};
        }
        if (const auto* list = dyn_cast<InitListExpr>(expr); list && list->getNumInits() == 1)
            return expr_range(list->getInit(0), type, depth + 1);
        if (const auto* cast = dyn_cast<CastExpr>(expr)) {
            const auto* input = cast->getSubExpr();
            if (input->getType()->isIntegerType()) {
                const auto narrower = expr_range(input, input->getType(), depth + 1);
                if (fits(narrower, type_range(expr->getType())) && fits(narrower, limits))
                    return narrower;
            }
        } else if (expr->getType()->isIntegerType()) {
            if (const auto* op = dyn_cast<BinaryOperator>(expr);
                op && (arithmetic(op->getOpcode()) || op->getOpcode() == BO_And) &&
                op->getLHS()->getType()->isIntegerType() &&
                op->getRHS()->getType()->isIntegerType()) {
                const auto* lhs = op->getLHS();
                const auto* rhs = op->getRHS();
                const auto a = expr_range(lhs, lhs->getType(), depth + 1);
                const auto b = expr_range(rhs, rhs->getType(), depth + 1);
                Range result = type_range(expr->getType());
                if (arithmetic(op->getOpcode())) {
                    result = calculate(op->getOpcode(), a, b);
                } else {
                    // A nonnegative operand has no sign bit set. The AND can
                    // only clear further bits and cannot grow past that operand.
                    if (!a.min.isNegative()) result = {Int(Width, 0), a.max};
                    if (!b.min.isNegative() && b.max.slt(result.max))
                        result = {Int(Width, 0), b.max};
                }
                if (fits(result, type_range(expr->getType())) && fits(result, limits))
                    return result;
            }
            const auto narrower = type_range(expr->getType());
            if (fits(narrower, limits)) return narrower;
        }
        return limits;
    }

    static Range product(const Range& a, const Range& b) {
        const Int products[] = {a.min * b.min, a.min * b.max, a.max * b.min, a.max * b.max};
        Range result{products[0], products[0]};
        for (const auto& candidate : products) {
            if (candidate.slt(result.min)) result.min = candidate;
            if (candidate.sgt(result.max)) result.max = candidate;
        }
        return result;
    }

    void report(SourceLocation loc, bool narrowing = false) const {
        if (context.getSourceManager().isInSystemHeader(loc)) return;
        auto& diagnostics = context.getDiagnostics();
        const auto id = narrowing
                            ? diagnostics.getCustomDiagID(
                                  DiagnosticsEngine::Warning,
                                  "integer arithmetic result may not fit the destination")
                            : diagnostics.getCustomDiagID(DiagnosticsEngine::Warning,
                                                          "integer arithmetic needs a range proof");
        diagnostics.Report(loc, id);
    }

    bool index_uses_range_value(const Expr* index, unsigned depth = 0) const {
        if (depth == 12) return false;
        index = index->IgnoreParens();
        if (const auto* cast = dyn_cast<CastExpr>(index)) {
            if (cast->getCastKind() == CK_IntegralCast ||
                cast->getCastKind() == CK_LValueToRValue || cast->getCastKind() == CK_NoOp)
                return index_uses_range_value(cast->getSubExpr(), depth + 1);
        }
        if (const auto* list = dyn_cast<InitListExpr>(index); list && list->getNumInits() == 1)
            return index_uses_range_value(list->getInit(0), depth + 1);
        if (const auto* op = dyn_cast<BinaryOperator>(index)) {
            if (op->getOpcode() == BO_Comma) return index_uses_range_value(op->getRHS(), depth + 1);
            return index_uses_range_value(op->getLHS(), depth + 1) ||
                   index_uses_range_value(op->getRHS(), depth + 1);
        }
        if (const auto* op = dyn_cast<UnaryOperator>(index))
            return index_uses_range_value(op->getSubExpr(), depth + 1);
        if (const auto* choice = dyn_cast<ConditionalOperator>(index))
            return index_uses_range_value(choice->getTrueExpr(), depth + 1) ||
                   index_uses_range_value(choice->getFalseExpr(), depth + 1);
        if (const auto* source = variable(index);
            source && source->hasInit() && index_uses_range_value(source->getInit(), depth + 1)) {
            if (source->getType().isConstQualified()) return true;
            if (!source->hasLocalStorage() || !source->getType()->isIntegerType() ||
                source->getType().isVolatileQualified())
                return false;
            const auto* function = enclosing_function(context, *index);
            return function && function->hasBody() &&
                   LocalReads(context, source, false).TraverseStmt(function->getBody());
        }

        const auto* call = dyn_cast<CXXMemberCallExpr>(index);
        const auto* method = call ? call->getMethodDecl() : nullptr;
        if (!method || !method->getIdentifier() || method->getName() != "value") return false;
        const auto* spec = dyn_cast<ClassTemplateSpecializationDecl>(method->getParent());
        return spec &&
               spec->getSpecializedTemplate()->getQualifiedNameAsString() == "rut::range_int";
    }

    void check_index(const Expr& index) const {
        if (index.isTypeDependent() || index.isValueDependent() ||
            context.getSourceManager().isInSystemHeader(index.getExprLoc()) ||
            !index_uses_range_value(&index))
            return;
        auto& diagnostics = context.getDiagnostics();
        const auto id = diagnostics.getCustomDiagID(
            DiagnosticsEngine::Warning, "use range_int::index() or at() for array indexing");
        diagnostics.Report(index.getExprLoc(), id) << index.getSourceRange();
    }

    bool bounded_loop_step(const UnaryOperator& step) const {
        if (!step.isIncrementDecrementOp()) return false;
        const auto* counter = variable(step.getSubExpr());
        if (!counter || !counter->getType()->isIntegerType() ||
            counter->getType().isVolatileQualified())
            return false;
        const auto parents = context.getParents(step);
        if (parents.size() != 1) return false;
        const auto* loop = parents[0].get<ForStmt>();
        if (!loop || loop->getInc() != &step || !loop->getCond()) return false;
        const auto* init = dyn_cast_or_null<DeclStmt>(loop->getInit());
        if (!init || !init->isSingleDecl() || init->getSingleDecl() != counter ||
            !counter->getInit() || !counter->getInit()->getIntegerConstantExpr(context))
            return false;
        const auto* comparison = dyn_cast<BinaryOperator>(loop->getCond()->IgnoreParenImpCasts());
        if (!comparison) return false;
        const Expr* cursor = comparison->getLHS();
        const Expr* bound = comparison->getRHS();
        auto code = comparison->getOpcode();
        if (variable(cursor) != counter) {
            std::swap(cursor, bound);
            if (code != BO_LT && code != BO_GT) return false;
            code = BinaryOperator::reverseComparisonOp(code);
        }
        if (variable(cursor) != counter || code != (step.isIncrementOp() ? BO_LT : BO_GT) ||
            !cursor->getType()->isIntegerType() || !bound->getType()->isIntegerType())
            return false;
        const auto limits = type_range(counter->getType());
        if (!fits(limits, type_range(cursor->getType()))) return false;
        const auto threshold = expr_range(bound, bound->getType());
        const bool guarded =
            step.isIncrementOp() ? threshold.max.sle(limits.max) : threshold.min.sge(limits.min);
        if (!guarded) return false;
        // RecursiveASTVisitor takes mutable nodes, but LocalReads only inspects them.
        auto reads = LocalReads(context, counter, false);
        return reads.TraverseStmt(const_cast<Expr*>(loop->getCond())) &&
               reads.TraverseStmt(const_cast<Stmt*>(loop->getBody()));
    }

public:
    explicit IntegerArithmeticVisitor(ASTContext& context) : context(context) {}

    bool shouldVisitTemplateInstantiations() const { return true; }

    bool VisitArraySubscriptExpr(const ArraySubscriptExpr* expr) {
        check_index(*expr->getIdx());
        return true;
    }

    bool VisitCXXOperatorCallExpr(const CXXOperatorCallExpr* expr) {
        if (expr->getOperator() == OO_Subscript)
            for (unsigned i = 1; i < expr->getNumArgs(); ++i) check_index(*expr->getArg(i));
        return true;
    }

    bool VisitCXXMemberCallExpr(const CXXMemberCallExpr* expr) {
        const auto* callee = expr->getMethodDecl();
        if (callee && callee->getOverloadedOperator() == OO_Subscript)
            for (const auto* argument : expr->arguments()) check_index(*argument);
        return true;
    }

    bool VisitBinaryOperator(const BinaryOperator* op) {
        if (!op->getType()->isIntegerType() || op->isTypeDependent() || op->isValueDependent() ||
            context.getSourceManager().isInSystemHeader(op->getOperatorLoc()))
            return true;
        const auto kind = op->getOpcode();
        if (kind != BO_Add && kind != BO_Sub && kind != BO_Mul && kind != BO_AddAssign &&
            kind != BO_SubAssign && kind != BO_MulAssign && kind != BO_Div && kind != BO_Rem &&
            kind != BO_DivAssign && kind != BO_RemAssign && kind != BO_Shl && kind != BO_Shr &&
            kind != BO_ShlAssign && kind != BO_ShrAssign)
            return true;
        const auto* compound = dyn_cast<CompoundAssignOperator>(op);
        const auto arithmetic_type =
            compound ? compound->getComputationResultType() : op->getType();
        const auto lhs_type =
            compound ? compound->getComputationLHSType() : op->getLHS()->getType();
        const auto rhs_type = op->getRHS()->getType();
        if (!arithmetic_type->isIntegerType() || !lhs_type->isIntegerType() ||
            !rhs_type->isIntegerType())
            return true;
        const auto a = expr_range(op->getLHS(), lhs_type);
        const auto b = expr_range(op->getRHS(), rhs_type);
        const auto limits = type_range(arithmetic_type);
        if (kind == BO_Div || kind == BO_Rem || kind == BO_DivAssign || kind == BO_RemAssign) {
            const Int negative_one(Width, -1, true);
            if ((b.min.isNonPositive() && !b.max.isNegative()) ||
                (arithmetic_type->isSignedIntegerType() && a.min == limits.min &&
                 b.min.sle(negative_one) && b.max.sge(negative_one)) ||
                (compound && !fits(limits, type_range(op->getType()))))
                report(op->getOperatorLoc());
            return true;
        }
        if (kind == BO_Shl || kind == BO_Shr || kind == BO_ShlAssign || kind == BO_ShrAssign) {
            const auto width = context.getIntWidth(arithmetic_type);
            if (b.min.isNegative() || b.max.sge(Int(Width, width))) {
                report(op->getOperatorLoc());
            } else if (kind == BO_Shl || kind == BO_ShlAssign) {
                const auto min_factor = Int::getOneBitSet(Width, b.min.getZExtValue());
                const auto max_factor = Int::getOneBitSet(Width, b.max.getZExtValue());
                const auto result = product(a, {min_factor, max_factor});
                if (!fits(result, limits) || !fits(result, type_range(op->getType())))
                    report(op->getOperatorLoc());
            }
            return true;
        }
        const Range result = calculate(kind, a, b);
        if (!fits(result, limits) || !fits(result, type_range(op->getType())))
            report(op->getOperatorLoc());
        return true;
    }

    bool VisitCastExpr(const CastExpr* cast) {
        if (cast->getCastKind() != CK_IntegralCast || cast->isTypeDependent() ||
            cast->isValueDependent() ||
            context.getSourceManager().isInSystemHeader(cast->getExprLoc()))
            return true;
        const auto* op = dyn_cast<BinaryOperator>(cast->getSubExpr()->IgnoreParens());
        if (!op || !arithmetic(op->getOpcode()) || !op->getType()->isIntegerType() ||
            !cast->getType()->isIntegerType())
            return true;
        if (!fits(expr_range(op, op->getType()), type_range(cast->getType())))
            report(cast->getExprLoc(), true);
        return true;
    }

    bool VisitUnaryOperator(const UnaryOperator* op) {
        if (!op->getType()->isIntegerType() || op->isTypeDependent() || op->isValueDependent() ||
            context.getSourceManager().isInSystemHeader(op->getOperatorLoc()) ||
            (!op->isIncrementDecrementOp() && op->getOpcode() != UO_Minus))
            return true;
        const auto value = expr_range(op->getSubExpr(), op->getType());
        const Int one(Width, 1);
        const auto result = op->getOpcode() == UO_Minus ? Range{-value.max, -value.min}
                            : op->isIncrementOp()       ? Range{value.min + one, value.max + one}
                                                        : Range{value.min - one, value.max - one};
        if (!fits(result, type_range(op->getType())) && !bounded_loop_step(*op))
            report(op->getOperatorLoc());
        return true;
    }
};

class IntegerArithmeticConsumer : public ASTConsumer {
    void HandleTranslationUnit(ASTContext& context) override {
        IntegerArithmeticVisitor(context).TraverseDecl(context.getTranslationUnitDecl());
    }
};

class IntegerArithmeticAction : public PluginASTAction {
    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance&, llvm::StringRef) override {
        return std::make_unique<IntegerArithmeticConsumer>();
    }

    bool ParseArgs(const CompilerInstance&, const std::vector<std::string>&) override {
        return true;
    }
};
}  // namespace

static FrontendPluginRegistry::Add<SignedConversionAction> registration(
    "rut-u64-to-i64",
    "Require range proofs for conversions from unsigned to signed 64-bit integers");

static FrontendPluginRegistry::Add<OverflowResultAction> overflow_registration(
    "rut-overflow-result", "Require explicit error returns for checked arithmetic");

static FrontendPluginRegistry::Add<IntegerArithmeticAction> arithmetic_registration(
    "rut-integer-arithmetic", "Find native integer operations without a type-range proof");
