// Examine Clang's optimized, signed-overflow-instrumented audit build.
// A remaining handler is an operation LLVM could not prove representable.
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

// A signed short increment computes in int, then converts back to short.
// Identify conversions directly consuming an arithmetic result before LLVM
// rewrites it. Other conversions do not belong to this check.
static bool isArithmeticConversion(const CallBase& call) {
    Value* value = call.getArgOperand(1);
    while (isa<ZExtInst, SExtInst>(value)) value = cast<Instruction>(value)->getOperand(0);
    if (auto* op = dyn_cast<BinaryOperator>(value))
        return op->getOpcode() == Instruction::Add || op->getOpcode() == Instruction::Sub;
    auto* extract = dyn_cast<ExtractValueInst>(value);
    if (!extract || extract->getIndices().size() != 1 || extract->getIndices()[0] != 0)
        return false;
    auto* arithmetic = dyn_cast<IntrinsicInst>(extract->getAggregateOperand());
    return arithmetic && (arithmetic->getIntrinsicID() == Intrinsic::sadd_with_overflow ||
                          arithmetic->getIntrinsicID() == Intrinsic::ssub_with_overflow);
}

// A strict signed comparison against any value excludes one extreme.
// Use only comparisons that hold on every path to this use.
static bool excludesExtreme(Value* value,
                            BasicBlock* block,
                            const DominatorTree& dom,
                            bool upper,
                            DenseMap<std::pair<Value*, BasicBlock*>, bool>& seen) {
    auto key = std::make_pair(value, block);
    if (auto it = seen.find(key); it != seen.end()) return it->second;
    if (seen.size() >= 128) return false;
    seen[key] = false;  // A cyclic dependency cannot establish its own bound.
    for (auto* node = dom.getNode(block); node; node = node->getIDom()) {
        auto* branch = dyn_cast<BranchInst>(node->getBlock()->getTerminator());
        if (!branch || !branch->isConditional()) continue;
        auto* cmp = dyn_cast<ICmpInst>(branch->getCondition());
        if (!cmp) continue;
        auto pred = cmp->getPredicate();
        if (cmp->getOperand(0) != value) {
            if (cmp->getOperand(1) != value) continue;
            pred = ICmpInst::getSwappedPredicate(pred);
        }
        auto strict = upper ? ICmpInst::ICMP_SLT : ICmpInst::ICMP_SGT;
        unsigned edge = pred == strict ? 0 : 1;
        if (edge && ICmpInst::getInversePredicate(pred) != strict) continue;
        if (dom.dominates(BasicBlockEdge(branch->getParent(), branch->getSuccessor(edge)), block))
            return seen[key] = true;
    }
    // At a merge each incoming value must independently exclude the extreme.
    auto* phi = dyn_cast<PHINode>(value);
    if (!phi) return false;
    for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i)
        if (!excludesExtreme(phi->getIncomingValue(i), phi->getIncomingBlock(i), dom, upper, seen))
            return false;
    return seen[key] = true;
}

static void proveUnitSteps(Function& fn, DominatorTree& dom) {
    for (auto& block : fn) {
        for (auto& inst : block) {
            auto* call = dyn_cast<IntrinsicInst>(&inst);
            if (!call || (call->getIntrinsicID() != Intrinsic::sadd_with_overflow &&
                          call->getIntrinsicID() != Intrinsic::ssub_with_overflow))
                continue;
            auto* step = dyn_cast<ConstantInt>(call->getArgOperand(1));
            if (!step || step->getBitWidth() < 2 || (!step->isOne() && !step->isMinusOne()))
                continue;
            bool increment =
                step->isOne() == (call->getIntrinsicID() == Intrinsic::sadd_with_overflow);
            DenseMap<std::pair<Value*, BasicBlock*>, bool> seen;
            if (!excludesExtreme(call->getArgOperand(0), &block, dom, increment, seen)) continue;
            for (auto* user : call->users()) {
                auto* extract = dyn_cast<ExtractValueInst>(user);
                if (extract && extract->getIndices().size() == 1 && extract->getIndices()[0] == 1)
                    extract->replaceAllUsesWith(ConstantInt::getFalse(fn.getContext()));
            }
        }
    }
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    LLVMContext context;
    SMDiagnostic error;
    auto module = parseIRFile(argv[1], error, context);
    if (!module) {
        error.print(argv[0], errs());
        return 2;
    }
    if (auto* conversions = module->getFunction("__ubsan_handle_implicit_conversion")) {
        auto marker = module->getOrInsertFunction("rut_audit_arithmetic_conversion",
                                                  conversions->getFunctionType());
        for (auto* user : make_early_inc_range(conversions->users())) {
            auto* call = dyn_cast<CallBase>(user);
            if (!call) return 2;
            if (isArithmeticConversion(*call)) call->setCalledFunction(marker);
        }
    }
    auto operationFor = [](StringRef name) {
        return StringSwitch<StringRef>(name)
            .Case("__ubsan_handle_add_overflow", "+")
            .Case("__ubsan_handle_sub_overflow", "-")
            .Case("__ubsan_handle_negate_overflow", "unary -")
            .Case("rut_audit_arithmetic_conversion", "result conversion")
            .Default("");
    };

    // Keep the bodies containing arithmetic alive during optimization. Without
    // this, uncalled static functions and unused inline definitions disappear
    // before we can distinguish a range proof from whole-function deletion.
    SmallPtrSet<Function*, 32> roots;
    for (auto& fn : *module) {
        if (operationFor(fn.getName()).empty()) continue;
        for (auto* user : fn.users()) {
            auto* call = dyn_cast<CallBase>(user);
            if (!call) return 2;
            roots.insert(call->getFunction());
        }
    }
    if (roots.empty()) return 0;
    SmallVector<GlobalValue*> retained(roots.begin(), roots.end());
    appendToCompilerUsed(*module, retained);
    LoopAnalysisManager loops;
    FunctionAnalysisManager functions;
    CGSCCAnalysisManager sccs;
    ModuleAnalysisManager modules;
    PassBuilder builder;
    builder.registerLoopAnalyses(loops);
    builder.registerFunctionAnalyses(functions);
    builder.registerCGSCCAnalyses(sccs);
    builder.registerModuleAnalyses(modules);
    builder.crossRegisterProxies(loops, functions, sccs, modules);
    ModulePassManager prep;
    cantFail(builder.parsePassPipeline(prep, "function(mem2reg,early-cse)"));
    prep.run(*module, modules);
    for (auto* fn : roots) proveUnitSteps(*fn, functions.getResult<DominatorTreeAnalysis>(*fn));
    builder.buildPerModuleDefaultPipeline(OptimizationLevel::O2).run(*module, modules);

    for (auto& fn : *module) {
        auto operation = operationFor(fn.getName());
        if (operation.empty()) continue;
        for (auto* use : fn.users()) {
            auto* call = dyn_cast<CallBase>(use);
            auto* global =
                call ? dyn_cast<GlobalVariable>(call->getArgOperand(0)->stripPointerCasts())
                     : nullptr;
            auto* record = global && global->hasInitializer() ? global->getInitializer() : nullptr;
            auto* loc = record ? record->getAggregateElement(0u) : nullptr;
            auto* file = loc ? loc->getAggregateElement(0u) : nullptr;
            auto* line = loc ? dyn_cast_or_null<ConstantInt>(loc->getAggregateElement(1)) : nullptr;
            auto* col = loc ? dyn_cast_or_null<ConstantInt>(loc->getAggregateElement(2)) : nullptr;
            StringRef path;
            if (!file || !line || !col || !getConstantStringInfo(file, path)) {
                errs() << "Cannot resolve overflow handler location in " << argv[1] << "\n";
                return 2;
            }
            outs() << path << '\t' << line->getZExtValue() << '\t' << col->getZExtValue() << '\t'
                   << operation << '\n';
        }
    }
    return 0;
}
