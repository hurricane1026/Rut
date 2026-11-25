#include "clang/AST/Attr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/Builtins.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "llvm/ADT/FoldingSet.h"

using namespace clang;

namespace {
class OverflowFallbackVisitor : public RecursiveASTVisitor<OverflowFallbackVisitor> {
public:
    explicit OverflowFallbackVisitor(ASTContext& context) : context(context) {}

    bool VisitIfStmt(IfStmt* stmt) {
        if (auto* condition = stmt->getCond()) {
            checkBranch(condition, stmt->getThen(), stmt->getElse(), true);
            if (auto* otherwise = stmt->getElse())
                checkBranch(condition, otherwise, stmt->getThen(), false);
        }
        return true;
    }

    bool VisitBinaryOperator(BinaryOperator* assignment) {
        if (assignment->getOpcode() != BO_Assign) return true;
        const auto* fallback = dyn_cast<CallExpr>(assignment->getRHS()->IgnoreParenCasts());
        const auto* callee = fallback ? fallback->getDirectCallee() : nullptr;
        if (callee && isExactCounter(assignment->getLHS()) &&
            callee->getQualifiedNameAsString() == "rut::saturating_add") {
            diagnose(assignment->getOperatorLoc(), "exact counter cannot use a saturating result");
        }
        auto* choice = dyn_cast<ConditionalOperator>(assignment->getRHS()->IgnoreParenImpCasts());
        if (!choice) return true;
        for (bool branch : {true, false}) {
            const Expr* output = overflowOutput(choice->getCond(), branch);
            const Expr* success = branch ? choice->getFalseExpr() : choice->getTrueExpr();
            if (!output || (!sameDestination(output, assignment->getLHS()) &&
                            !sameDestination(output, success)))
                continue;
            diagnoseFallback(assignment->getOperatorLoc());
            break;
        }
        return true;
    }

    bool VisitCallExpr(CallExpr* call) {
        if (const Expr* output = checkedOutput(call); output && isExactCounter(output))
            diagnose(call->getExprLoc(),
                     "check overflow before storing a result in an exact counter");
        return true;
    }

private:
    ASTContext& context;

    static const Expr* overflowOutput(const Expr* condition, bool branch, bool followFlag = true) {
        condition = condition->IgnoreParenImpCasts();
        if (auto* flag = dyn_cast<DeclRefExpr>(condition)) {
            auto* local = dyn_cast<VarDecl>(flag->getDecl());
            if (followFlag && local && local->hasLocalStorage() &&
                local->getType().isConstQualified() && local->getInit())
                return overflowOutput(local->getInit(), branch, false);
        }
        if (auto* negate = dyn_cast<UnaryOperator>(condition))
            if (negate->getOpcode() == UO_LNot)
                return overflowOutput(negate->getSubExpr(), !branch, followFlag);
        return branch ? checkedOutput(dyn_cast<CallExpr>(condition)) : nullptr;
    }

    static const Expr* checkedOutput(const CallExpr* call) {
        if (!call || call->getNumArgs() != 3 || !call->getDirectCallee()) return nullptr;
        switch (call->getDirectCallee()->getBuiltinID()) {
            case Builtin::BI__builtin_add_overflow:
            case Builtin::BI__builtin_sub_overflow:
            case Builtin::BI__builtin_mul_overflow:
                break;
            default:
                return nullptr;
        }
        auto* address = dyn_cast<UnaryOperator>(call->getArg(2)->IgnoreParenImpCasts());
        return address && address->getOpcode() == UO_AddrOf ? address->getSubExpr() : nullptr;
    }

    static bool isExactCounter(const Expr* destination) {
        auto* member = dyn_cast<MemberExpr>(destination->IgnoreParenImpCasts());
        if (!member) return false;
        for (auto* attr : member->getMemberDecl()->specific_attrs<AnnotateAttr>())
            if (attr->getAnnotation() == "rut_exact_counter") return true;
        return false;
    }

    bool sameDestination(const Expr* left, const Expr* right) const {
        llvm::FoldingSetNodeID leftId, rightId;
        left->IgnoreParenImpCasts()->Profile(leftId, context, true);
        right->IgnoreParenImpCasts()->Profile(rightId, context, true);
        return leftId == rightId;
    }

    void checkBranch(const Expr* condition, const Stmt* branch, const Stmt* opposite, bool taken) {
        condition = condition->IgnoreParenImpCasts();
        if (auto* logical = dyn_cast<BinaryOperator>(condition);
            logical && logical->isLogicalOp()) {
            checkBranch(logical->getLHS(), branch, opposite, taken);
            checkBranch(logical->getRHS(), branch, opposite, taken);
            return;
        }
        const Expr* output = overflowOutput(condition, taken);
        if (!output) return;
        checkWrites(branch, output);
        if (auto* block = dyn_cast_or_null<CompoundStmt>(opposite); block && block->size() == 1)
            opposite = block->body_front();
        if (auto* copy = dyn_cast_or_null<BinaryOperator>(opposite);
            copy && copy->getOpcode() == BO_Assign && sameDestination(copy->getRHS(), output) &&
            !sameDestination(copy->getLHS(), output))
            checkWrites(branch, copy->getLHS());
    }

    void checkWrites(const Stmt* stmt, const Expr* output) {
        if (!stmt || isa<LambdaExpr>(stmt)) return;
        if (auto* assignment = dyn_cast<BinaryOperator>(stmt);
            assignment && assignment->isAssignmentOp() &&
            sameDestination(output, assignment->getLHS()))
            diagnoseFallback(assignment->getOperatorLoc());
        for (const auto* child : stmt->children()) checkWrites(child, output);
    }

    void diagnoseFallback(SourceLocation loc) {
        diagnose(loc,
                 "overflow branch replaces the checked result; propagate failure or use an "
                 "explicit saturating operation for a value whose contract is saturation");
    }

    template <unsigned N>
    void diagnose(SourceLocation loc, const char (&message)[N]) {
        if (context.getSourceManager().isInSystemHeader(loc)) return;
        auto& diagnostics = context.getDiagnostics();
        const auto id = diagnostics.getCustomDiagID(DiagnosticsEngine::Error, message);
        diagnostics.Report(loc, id);
    }
};

class OverflowFallbackConsumer : public ASTConsumer {
    void HandleTranslationUnit(ASTContext& context) override {
        OverflowFallbackVisitor(context).TraverseDecl(context.getTranslationUnitDecl());
    }
};

class OverflowFallbackAction : public PluginASTAction {
    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance&, llvm::StringRef) override {
        return std::make_unique<OverflowFallbackConsumer>();
    }

    bool ParseArgs(const CompilerInstance&, const std::vector<std::string>&) override {
        return true;
    }
};
}  // namespace

static FrontendPluginRegistry::Add<OverflowFallbackAction> registry(
    "rut-overflow-fallback", "Reject overflow recovery that overwrites the checked result");
