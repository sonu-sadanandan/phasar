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
#include "phasar/PhasarLLVM/Pointer/LLVMBasedAliasAnalysis.h"
#include "phasar/PhasarLLVM/DB/LLVMProjectIRDB.h"

#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/BasicAliasAnalysis.h"
#include "llvm/Analysis/ScopedNoAliasAA.h"
#include "llvm/Analysis/TypeBasedAliasAnalysis.h"


#include "DirectAliasComputer.h"
#include "AliasGraph.h"

using namespace llvm;
using namespace phasar;

static cl::opt<std::string> InputFilename(cl::Positional, cl::desc("<IR file>"), cl::init("-"));

int main(int argc, char **argv) {
    cl::ParseCommandLineOptions(argc, argv, "Alias Set Builder\n");

    LLVMContext Context;
    SMDiagnostic Err;
    std::unique_ptr<Module> Mod = llvm::parseIRFile(InputFilename, Err, Context);

    if (!Mod) {
        Err.print(argv[0], errs());
        return 1;
    }

    AliasGraph Graph;
    std::unordered_set<const Function *> AnalyzedFunctions;

    // Set up AAResults using PassBuilder
    // PassBuilder PB;
    // FunctionAnalysisManager FAM;
    // FAM.registerPass([&] {
    //     llvm::AAManager AA;
    //     AA.registerFunctionAnalysis<llvm::CFLAndersAA>();
    //     AA.registerFunctionAnalysis<llvm::TypeBasedAA>();
    //     AA.registerFunctionAnalysis<llvm::ScopedNoAliasAA>();
    //     AA.registerFunctionAnalysis<llvm::BasicAA>();

    //     return AA;
    //  });
    // PB.registerFunctionAnalyses(FAM);
    // ModuleAnalysisManager MAM;
    // PB.registerModuleAnalyses(MAM);
    // CGSCCAnalysisManager CGAM;
    // PB.registerCGSCCAnalyses(CGAM);
    // LoopAnalysisManager LAM;
    // PB.registerLoopAnalyses(LAM);
    // PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

    psr::LLVMProjectIRDB IRDB(InputFilename);
    if (!IRDB.isValid()) {
        //isValid() prints the error msg
        return 1;
    }

    psr::LLVMBasedAliasAnalysis AAObj(IRDB, true, psr::AliasAnalysisType::CFLAnders);
    

    for (Function &F : *Mod) {
        if (F.isDeclaration()) continue;

        //auto &AA = FAM.getResult<AAManager>(F);
        // const DataLayout &DL = Mod->getDataLayout();

        DirectAliasComputer Computer(
            *AAObj.getAAResults(&F), AnalyzedFunctions,
            [&](const Value *A, const Value *B, AliasKind Kind) {
                Graph.addAlias(A, B, Kind);
            }
        );
        Computer.computeDirectAliases(&F);
    }

    Graph.printAliasClusters();
    Graph.printAliasMap();
    return 0;
}
