// Check native integer conversions after Clang resolves aliases and promotions.
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"

using namespace clang;

namespace {
class SignedConversionVisitor : public RecursiveASTVisitor<SignedConversionVisitor> {
    ASTContext& context;

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
        if (const auto value = input->getIntegerConstantExpr(context);
            value && !value->isNegative() && value->getActiveBits() < 64)
            return true;
        auto& diagnostics = context.getDiagnostics();
        const auto id = diagnostics.getCustomDiagID(DiagnosticsEngine::Warning,
                                                    "u64 to i64 conversion requires a range proof");
        diagnostics.Report(cast->getExprLoc(), id) << cast->getSourceRange();
        return true;
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
