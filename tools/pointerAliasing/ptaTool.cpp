#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/Passes.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/Analysis/AliasAnalysisEvaluator.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/BasicAliasAnalysis.h"
#include "llvm/Analysis/ScopedNoAliasAA.h"
#include "llvm/Analysis/TypeBasedAliasAnalysis.h"

#include "phasar/PhasarLLVM/Pointer/AliasAnalysisView.h"
#include "phasar/PhasarLLVM/DB/LLVMProjectIRDB.h"

#include "heuristics/HeuristicUtils.h"
#include "DirectAliasComputer.h"
#include "AliasGraph.h"
#include <chrono>
#include <iomanip>

using namespace llvm;
using namespace phasar;

static cl::opt<std::string> InputFilename(cl::Positional, cl::desc("<IR file>"), cl::init("-"));

int main(int argc, char **argv) {
    cl::ParseCommandLineOptions(argc, argv, "Alias Set Builder\n");

    AliasGraph Graph;
    std::unordered_set<const Function *> AnalyzedFunctions;

    psr::LLVMProjectIRDB IRDB(InputFilename);
    if (!IRDB.isValid()) {
        return 1;
    }

    auto *Mod = IRDB.getModule();
    auto AAObj = psr::AliasAnalysisView::create(IRDB, true, psr::AliasAnalysisType::CFLAnders);

    auto dataStructureStart = std::chrono::high_resolution_clock::now();

    std::unique_ptr<DirectAliasComputer> Computer;
    size_t TotalPointers = 0;

    for (Function &F : *IRDB.getModule()) {
        if (F.isDeclaration()) continue;

        auto FAV = AAObj->getAAResults(&F); // This returns by value

        Computer = std::make_unique<DirectAliasComputer>(
            AAObj->getAAResults(&F), AnalyzedFunctions,
            [&](const Value *A, const Value *B, AliasKind Kind) {
                Graph.addAlias(A, B, Kind);
            },
            [&](const Value *Ptr) {
                Graph.ensureExists(Ptr);
            }
        );
        Computer->computeDirectAliases(&F);
        Graph.promoteByStoreLoad(F, Graph, FAV);
        TotalPointers += Computer->getTotalPointerCount();
    }
    

    // for (Function &F : *Mod) {
    //     if (F.isDeclaration()) continue;

    //     for (auto &I : instructions(F)) {
    //         if (auto *Call = dyn_cast<CallBase>(&I)) {
    //             auto *Callee = Call->getCalledFunction();
    //             if (!Callee || Callee->isDeclaration()) continue;

    //             unsigned ArgIdx = 0;
    //             static int CallCounter = 0;
    //             for (auto AI = Callee->arg_begin(), AE = Callee->arg_end();
    //                  AI != AE && ArgIdx < Call->arg_size();
    //                  ++AI, ++ArgIdx) {

    //                 const Value *Actual = Call->getArgOperand(ArgIdx);
    //                 std::string FormalName = Callee->getName().str() + "_callsite_" + std::to_string(CallCounter++) + "_arg_" + std::to_string(ArgIdx);

    //                 Graph.addAlias(Actual, FormalName, AliasKind::MustAlias);
    //             }

    //             if (Callee->getReturnType()->isPointerTy() && Call->getType()->isPointerTy()) {
    //                 std::string RetNode = Callee->getName().str() + "_ret" + std::to_string(CallCounter);
    //                 Graph.addAlias(Call, RetNode, AliasKind::MayAlias);
    //             }
    //         }
    //     }
    // }  

    llvm::outs() << "Total pointers analyzed: " << TotalPointers << "\n\n";

    Graph.addHeuristicMustAliasEdges(Mod->getDataLayout());
    HeuristicUtils::applyAllHeuristics(Graph);

    auto dataStructureEnd = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> TimeForDataStructure = dataStructureEnd - dataStructureStart;
    llvm::outs() << llvm::format("\n[Timing] Data Structure computation took in s: %.6f s.\n\n", TimeForDataStructure.count());
    auto ClusterStart = std::chrono::high_resolution_clock::now();

    // computing clusters
    auto Clusters = Graph.computeAliasClusters();

    auto ClusterEnd = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> ms_diff = ClusterEnd - ClusterStart;
    llvm::outs() << "\n Clusters computed: " << Clusters.size() << "\n";
    llvm::outs() << llvm::format("\n[Timing] Cluster computation took in s: %.6f s.\n", ms_diff.count());
    auto FinalExecution = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> totalTime = FinalExecution - dataStructureStart;
    llvm::outs() << llvm::format("\n[Timing] Total computation took in s: %.6f s.\n\n", totalTime.count());

    // Graph.logAliasMap(Graph.aliasMap, "/workspaces/phasar/build/aliasMap_contextual.txt");
    //Graph.printAliasClusters(Clusters);
    return 0;
}

