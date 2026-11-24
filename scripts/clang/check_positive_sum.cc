// Clang Static Analyzer checker. Loaded only by the CI analysis compiler.
#include "clang/AST/Attr.h"
#include "clang/Basic/Builtins.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include <algorithm>
#include <memory>
#include <optional>

using namespace clang;
using namespace ento;

// Remember the path facts at the addition, before any post-addition test.
REGISTER_SET_WITH_PROGRAMSTATE(UnprovenSums, SymbolRef)

REGISTER_SET_WITH_PROGRAMSTATE(PositiveSums, SymbolRef)
REGISTER_SET_WITH_PROGRAMSTATE(SumValues, SymbolRef)
REGISTER_SET_WITH_PROGRAMSTATE(UnprovenConversions, SymbolRef)

enum class SumRange { Unknown, Representable, Positive };
REGISTER_MAP_WITH_PROGRAMSTATE(PendingSums, const BinaryOperator*, SumRange)

namespace {
class PositiveSum : public Checker<check::PreStmt<BinaryOperator>,
                                   check::PostStmt<BinaryOperator>,
                                   check::PostStmt<CastExpr>,
                                   check::Bind,
                                   check::PostCall,
                                   check::PreCall> {
    BugType bug{this, "Unproven positive integer", "Rut arithmetic"};

public:
    void checkPreStmt(const BinaryOperator* op, CheckerContext& c) const {
        if ((op->getOpcode() != BO_Add && op->getOpcode() != BO_AddAssign) ||
            !op->getType()->isSignedIntegerType())
            return;
        auto state = c.getState();
        auto& builder = c.getSValBuilder();
        SVal lhs = c.getSVal(op->getLHS());
        if (auto location = lhs.getAs<Loc>()) lhs = state->getSVal(*location);
        SVal rhs = c.getSVal(op->getRHS());
        unsigned width = c.getASTContext().getIntWidth(op->getType());
        auto bound = [&](bool lower) -> std::optional<llvm::APInt> {
            auto* a = lower ? builder.getMinValue(state, lhs) : builder.getMaxValue(state, lhs);
            auto* b = lower ? builder.getMinValue(state, rhs) : builder.getMaxValue(state, rhs);
            if (!a || !b) return std::nullopt;
            unsigned bits = std::max({width, a->getBitWidth(), b->getBitWidth()}) + 2;
            llvm::APInt left = a->extOrTrunc(bits);
            llvm::APInt right = b->extOrTrunc(bits);
            return left + right;
        };
        auto low = bound(true);
        auto high = bound(false);
        // Concrete arithmetic may be folded into a plain integer, losing its
        // symbol before the store or call. Diagnose definite signed overflow
        // here while the mathematical range is still available.
        if (op->getOpcode() == BO_Add && low && high &&
            ((!low->isNegative() && !low->isSignedIntN(width)) ||
             (high->isNegative() && !high->isSignedIntN(width)))) {
            if (auto* node = c.generateErrorNode()) {
                auto report = std::make_unique<PathSensitiveBugReport>(
                    bug, "Signed addition exceeds its representable range", node);
                report->addRange(op->getSourceRange());
                c.emitReport(std::move(report));
            }
            return;
        }
        auto range = SumRange::Unknown;
        if (low && high && low->isSignedIntN(width) && high->isSignedIntN(width))
            range = low->isStrictlyPositive() ? SumRange::Positive : SumRange::Representable;
        // Independent operand ranges lose the relation in a <= MAX - b.
        // The subtraction itself is representable when b is nonnegative.
        if (range == SumRange::Unknown && low && low->isSignedIntN(width) &&
            op->getOpcode() == BO_Add) {
            const auto* min_rhs = builder.getMinValue(state, rhs);
            if (min_rhs && !min_rhs->isNegative()) {
                auto maximum =
                    builder.makeIntVal(llvm::APSInt(llvm::APInt::getSignedMaxValue(width), false));
                auto limit = builder.evalBinOp(state, BO_Sub, maximum, rhs, op->getType());
                auto fits = builder.evalBinOp(
                    state, BO_LE, lhs, limit, c.getASTContext().getLogicalOperationType());
                if (auto proof = fits.getAs<DefinedSVal>(); proof && !state->assume(*proof, false))
                    range =
                        low->isStrictlyPositive() ? SumRange::Positive : SumRange::Representable;
            }
        }
        c.addTransition(state->set<PendingSums>(op, range));
    }

    void checkPostStmt(const BinaryOperator* op, CheckerContext& c) const {
        auto state = c.getState();
        const auto* range = state->get<PendingSums>(op);
        if (!range) return;
        auto next = state->remove<PendingSums>(op);
        SVal result = c.getSVal(op);
        if (auto location = result.getAs<Loc>()) result = state->getSVal(*location);
        if (auto symbol = result.getAsSymbol()) {
            next = next->add<SumValues>(symbol);
            if (*range == SumRange::Positive) next = next->add<PositiveSums>(symbol);
            if (*range == SumRange::Unknown) next = next->add<UnprovenSums>(symbol);
        }
        c.addTransition(next);
    }

    void checkPostStmt(const CastExpr* cast, CheckerContext& c) const {
        if (cast->getCastKind() != CK_IntegralCast) return;
        auto state = c.getState();
        auto input = c.getSVal(cast->getSubExpr());
        auto source = input.getAsSymbol();
        auto converted = c.getSVal(cast).getAsSymbol();
        if (!source || !converted || !state->contains<SumValues>(source)) return;
        auto next = state->add<SumValues>(converted);
        auto& builder = c.getSValBuilder();
        auto width = c.getASTContext().getIntWidth(cast->getType());
        auto fits = [&](const llvm::APSInt* bound) {
            if (!bound) return false;
            llvm::APInt extended = bound->extOrTrunc(std::max(width, bound->getBitWidth()) + 1);
            return cast->getType()->isSignedIntegerType() ? extended.isSignedIntN(width)
                                                          : extended.isIntN(width);
        };
        if (!fits(builder.getMinValue(state, input)) || !fits(builder.getMaxValue(state, input)))
            next = next->add<UnprovenConversions>(converted);
        c.addTransition(next);
    }

    void checkPostCall(const CallEvent& call, CheckerContext& c) const {
        auto* fn = dyn_cast_or_null<FunctionDecl>(call.getDecl());
        if (!fn || fn->getBuiltinID() != Builtin::BI__builtin_add_overflow) return;
        auto state = c.getState();
        auto overflow = call.getReturnValue().getAs<DefinedOrUnknownSVal>();
        auto output = call.getArgSVal(2).getAs<Loc>();
        if (!output) return;
        if (auto symbol = state->getSVal(*output).getAsSymbol()) {
            auto next = state->add<SumValues>(symbol);
            if (!overflow || state->assume(*overflow, true)) next = next->add<UnprovenSums>(symbol);
            c.addTransition(next);
        }
    }

    void checkBind(SVal location, SVal value, const Stmt* stmt, bool, CheckerContext& c) const {
        auto* field = dyn_cast_or_null<FieldRegion>(location.getAsRegion());
        if (!stmt || !field || !annotated(field->getDecl(), "rut_positive_sum")) return;
        auto* op = dyn_cast_or_null<BinaryOperator>(stmt);
        // Bind precedes PostStmt for compound assignment.
        if (op && op->getOpcode() == BO_AddAssign) {
            auto* range = c.getState()->get<PendingSums>(op);
            requirePositive(c,
                            value,
                            stmt->getSourceRange(),
                            !range || *range == SumRange::Unknown,
                            range && *range == SumRange::Positive);
            return;
        }
        if (op && op->getOpcode() == BO_Assign) {
            auto* rhs = dyn_cast<BinaryOperator>(op->getRHS()->IgnoreParenCasts());
            if (rhs && rhs->getOpcode() == BO_Add) {
                requirePositive(c, value, stmt->getSourceRange());
                return;
            }
        }
        auto symbol = value.getAsSymbol();
        while (auto* cast = dyn_cast_or_null<SymbolCast>(symbol)) symbol = cast->getOperand();
        if (symbol && c.getState()->contains<SumValues>(symbol))
            requirePositive(c, value, stmt->getSourceRange());
    }

    void checkPreCall(const CallEvent& call, CheckerContext& c) const {
        auto params = call.parameters();
        for (unsigned i = 0; i < params.size() && i < call.getNumArgs(); ++i) {
            if (annotated(params[i], "rut_positive"))
                requirePositive(c, call.getArgSVal(i), call.getArgSourceRange(i));
            if (annotated(params[i], "rut_representable")) {
                // The factory checks the domain itself. Arithmetic producing its
                // input must already be representable before that check runs.
                requirePositive(c, call.getArgSVal(i), call.getArgSourceRange(i), false, true);
            }
        }
    }

private:
    static bool annotated(const Decl* decl, StringRef contract) {
        for (const auto* attr : decl->specific_attrs<AnnotateAttr>())
            if (attr->getAnnotation() == contract) return true;
        return false;
    }

    void requirePositive(CheckerContext& c,
                         SVal value,
                         SourceRange source,
                         bool unsafe = false,
                         bool positive = false) const {
        auto state = c.getState();
        auto* minimum = c.getSValBuilder().getMinValue(state, value);
        bool lossy = false;
        if (auto symbol = value.getAsSymbol()) {
            positive |= state->contains<PositiveSums>(symbol);
            for (auto dependency : symbol->symbols()) {
                unsafe |= state->contains<UnprovenSums>(dependency);
                lossy |= state->contains<UnprovenConversions>(dependency);
            }
        }
        if (!unsafe && !lossy && (positive || (minimum && minimum->isStrictlyPositive()))) return;
        if (auto* node = c.generateNonFatalErrorNode()) {
            auto report = std::make_unique<PathSensitiveBugReport>(
                bug,
                lossy    ? "Sum may be out of range before integer conversion"
                : unsafe ? "Signed addition may overflow before positive use"
                         : "Result must be proven strictly positive before use",
                node);
            report->addRange(source);
            c.emitReport(std::move(report));
        }
    }
};
}  // namespace

extern "C" void clang_registerCheckers(CheckerRegistry& registry) {
    registry.addChecker<PositiveSum>("rut.PositiveSum", "Check positive integer contracts", "");
}
extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
