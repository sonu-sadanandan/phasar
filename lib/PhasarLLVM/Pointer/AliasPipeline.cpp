#include "phasar/PhasarLLVM/Pointer/AliasPipeline.h"

#include "phasar/PhasarLLVM/Pointer/DirectAliasComputer.h"
#include "phasar/PhasarLLVM/Pointer/HeuristicUtils.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/raw_ostream.h"

#include <chrono>

namespace psr {

AliasPipelineResult buildAliasClusters(LLVMProjectIRDB &IRDB,
                                       AliasAnalysisType AATy) {
  AliasPipelineResult R;
  R.Graph = std::make_unique<AliasGraph>();

  // Create an AA view for this IRDB/module with the requested AA type
  auto AAView = AliasAnalysisView::create(IRDB, true, AATy);

  std::unordered_set<const llvm::Function *> AnalyzedFunctions;
  std::unique_ptr<phasar::DirectAliasComputer> Computer;

  auto *Mod = IRDB.getModule();
  const auto &DL = Mod->getDataLayout();

  auto TStart = std::chrono::high_resolution_clock::now();

  for (llvm::Function &F : *Mod) {
    if (F.isDeclaration())
      continue;

    auto FAV = AAView->getAAResults(&F);

    Computer = std::make_unique<phasar::DirectAliasComputer>(
        FAV, AnalyzedFunctions,
        [&](const llvm::Value *A, const llvm::Value *B, AliasKind Kind) {
          R.Graph->addAlias(A, B, Kind);
        },
        [&](const llvm::Value *Ptr) { R.Graph->ensureExists(Ptr); });

    Computer->computeDirectAliases(&F);
    R.TotalPointers += Computer->getTotalPointerCount();

    // Heuristic 5 (store→load) that needs alias queries between stores
    R.Graph->promoteByStoreLoad(F, *R.Graph, FAV);
  }

  // Add more MustAlias edges from structural patterns (heuristic 4)
  R.Graph->addHeuristicMustAliasEdges(DL);

  HeuristicUtils::applyAllHeuristics(*R.Graph);

  R.Clusters = std::make_unique<AliasClusterInfo>(*R.Graph);

  auto TEnd = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> Secs = TEnd - TStart;
  llvm::outs() << "[AliasPipeline] Built graph + clusters in " << Secs.count()
               << "s, total pointers: " << R.TotalPointers << "\n";

  return R;
}

} // namespace psr
