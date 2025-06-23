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
#include "phasar/PhasarLLVM/Pointer/AliasAnalysisView.h"
#include "phasar/PhasarLLVM/DB/LLVMProjectIRDB.h"

#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/BasicAliasAnalysis.h"
#include "llvm/Analysis/ScopedNoAliasAA.h"
#include "llvm/Analysis/TypeBasedAliasAnalysis.h"


#include "phasar/Pointer/DirectAliasComputer.h"
#include "phasar/Pointer/AliasGraph.h"

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

    auto AAObj = psr::AliasAnalysisView::create(IRDB, true, psr::AliasAnalysisType::CFLAnders);
    //psr::LLVMBasedAliasAnalysis AAObj(IRDB, true, psr::AliasAnalysisType::CFLAnders);
    

    for (Function &F : *IRDB.getModule()) {
        if (F.isDeclaration()) continue;

        DirectAliasComputer Computer(
            AAObj->getAAResults(&F), AnalyzedFunctions,
            [&](const Value *A, const Value *B, AliasKind Kind) {
                Graph.addAlias(A, B, Kind);
            },
            [&](const Value *Ptr) {
                Graph.ensureExists(Ptr);
            }
        );
        Computer.computeDirectAliases(&F);
    }

    auto Clusters = Graph.computeAliasClusters();
    Graph.printAliasClusters(Clusters);

    return 0;
}
