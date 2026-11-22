// Analysis tool only. The runtime does not link Clang.
#include "clang/AST/ASTContext.h"
#include "clang/AST/ExprCXX.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Analysis/CFG.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include <deque>
#include <optional>
#include <set>

using namespace clang;
using namespace clang::ast_matchers;

namespace {
const VarDecl* variable(const Expr* e) {
    const auto* ref = dyn_cast_or_null<DeclRefExpr>(e ? e->IgnoreParenImpCasts() : nullptr);
    return ref ? dyn_cast<VarDecl>(ref->getDecl()) : nullptr;
}

// Return the branch on which this comparison proves the step is legal.
// C++20 may implement != as !(operator==(...)).
std::optional<bool> guarded_branch(const Expr* e, const VarDecl* cursor, StringRef boundary) {
    if (!e) return {};
    e = e->IgnoreParenImpCasts();
    if (const auto* rewrite = dyn_cast<CXXRewrittenBinaryOperator>(e))
        return guarded_branch(rewrite->getSemanticForm(), cursor, boundary);
    if (const auto* unary = dyn_cast<UnaryOperator>(e); unary && unary->getOpcode() == UO_LNot) {
        auto result = guarded_branch(unary->getSubExpr(), cursor, boundary);
        if (result) return !*result;
        return {};
    }
    const auto* op = dyn_cast<CXXOperatorCallExpr>(e);
    if (!op || (op->getOperator() != OO_EqualEqual && op->getOperator() != OO_ExclaimEqual))
        return {};
    const auto* a = variable(op->getArg(0));
    const auto* b = variable(op->getArg(1));
    const auto* limit = a == cursor ? b : b == cursor ? a : nullptr;
    if (!limit || limit->getName() != boundary || !limit->getType().isConstQualified()) return {};
    return op->getOperator() == OO_ExclaimEqual;
}

// Explicit aliases need interprocedural tracking. Fail closed for cursors whose
// storage can be modified this way, instead of reusing an earlier comparison.
bool escapes(const FunctionDecl* fn, const VarDecl* cursor, ASTContext& context) {
    auto ref = declRefExpr(to(varDecl(equalsNode(cursor))));
    auto storage = ignoringParenImpCasts(
        expr(anyOf(ref, memberExpr(hasObjectExpression(ignoringParenImpCasts(ref))))));
    auto mutable_ref = referenceType(pointee(qualType(unless(isConstQualified()))));
    auto escape =
        stmt(anyOf(unaryOperator(hasOperatorName("&"), hasUnaryOperand(storage)),
                   declStmt(has(varDecl(hasType(mutable_ref), hasInitializer(storage)))),
                   callExpr(unless(cxxOperatorCallExpr()),
                            forEachArgumentWithParam(storage, parmVarDecl(hasType(mutable_ref))))));
    return !clang::ast_matchers::match(functionDecl(hasDescendant(escape)), *fn, context).empty();
}

class RingCheck : public MatchFinder::MatchCallback {
public:
    void onStartOfTranslationUnit() override {
        graph.reset();
        cached = nullptr;
    }

    void run(const MatchFinder::MatchResult& match) override {
        const auto* target = match.Nodes.getNodeAs<CXXOperatorCallExpr>("step");
        const auto* fn = match.Nodes.getNodeAs<FunctionDecl>("function");
        const auto* cursor = variable(target->getArg(0));
        const auto boundary = target->getOperator() == OO_PlusPlus ? "end" : "begin";
        if (cursor && prove(*match.Context, fn, target, cursor, boundary)) return;
        auto& diagnostics = match.Context->getDiagnostics();
        auto id = diagnostics.getCustomDiagID(DiagnosticsEngine::Error,
                                              "ring iterator step requires a comparison of this "
                                              "cursor with const '%0' since its last step");
        diagnostics.Report(target->getOperatorLoc(), id) << boundary;
    }

private:
    const FunctionDecl* cached = nullptr;
    std::unique_ptr<CFG> graph;

    bool prove(ASTContext& context,
               const FunctionDecl* fn,
               const Expr* target,
               const VarDecl* cursor,
               StringRef boundary) {
        if (fn != cached) {
            CFG::BuildOptions options;
            options.setAlwaysAdd(Stmt::CXXOperatorCallExprClass);
            graph = CFG::buildCFG(fn, fn->getBody(), &context, options);
            cached = fn;
        }
        if (!graph || escapes(fn, cursor, context)) return false;
        // Search both guarded and unguarded paths. A step consumes its proof.
        using State = std::pair<const CFGBlock*, bool>;
        std::deque<State> work{{&graph->getEntry(), false}};
        std::set<State> visited;
        bool reached = false;
        while (!work.empty()) {
            auto [block, safe] = work.front();
            work.pop_front();
            if (!visited.emplace(block, safe).second) continue;
            for (const auto& element : *block) {
                auto stmt = element.getAs<CFGStmt>();
                if (!stmt) continue;
                const Stmt* s = stmt->getStmt();
                if (s == target) {
                    reached = true;
                    if (!safe) return false;
                }
                if (const auto* op = dyn_cast<CXXOperatorCallExpr>(s);
                    op && op->getNumArgs() && variable(op->getArg(0)) == cursor &&
                    (op->getOperator() == OO_PlusPlus || op->getOperator() == OO_MinusMinus ||
                     op->getOperator() == OO_Equal))
                    safe = false;
                if (const auto* unary = dyn_cast<UnaryOperator>(s);
                    unary && unary->isIncrementDecrementOp()) {
                    const auto* member =
                        dyn_cast<MemberExpr>(unary->getSubExpr()->IgnoreParenImpCasts());
                    if (member && variable(member->getBase()) == cursor) safe = false;
                }
                if (const auto* write = dyn_cast<BinaryOperator>(s);
                    write && write->isAssignmentOp()) {
                    const auto* member =
                        dyn_cast<MemberExpr>(write->getLHS()->IgnoreParenImpCasts());
                    if (member && variable(member->getBase()) == cursor) safe = false;
                }
            }
            auto guard = guarded_branch(block->getLastCondition(), cursor, boundary);
            unsigned edge = 0;
            for (const auto& successor : block->succs()) {
                if (const auto* next = successor.getReachableBlock())
                    work.emplace_back(
                        next, guard && block->succ_size() == 2 ? (*guard == (edge == 0)) : safe);
                ++edge;
            }
        }
        return reached;
    }
};
}  // namespace

int main(int argc, const char** argv) {
    llvm::cl::OptionCategory category("Rut ring iterator checks");
    auto options = tooling::CommonOptionsParser::create(argc, argv, category);
    if (!options) {
        llvm::errs() << options.takeError();
        return 1;
    }
    tooling::ClangTool tool(options->getCompilations(), options->getSourcePathList());
    MatchFinder finder;
    RingCheck check;
    finder.addMatcher(
        cxxOperatorCallExpr(
            anyOf(hasOverloadedOperatorName("++"), hasOverloadedOperatorName("--")),
            hasArgument(0,
                        expr(hasType(qualType(hasCanonicalType(recordType(
                            hasDeclaration(cxxRecordDecl(hasName("::rut::IoUringPosition"))))))))),
            hasAncestor(functionDecl(isDefinition()).bind("function")))
            .bind("step"),
        &check);
    return tool.run(tooling::newFrontendActionFactory(&finder).get());
}
