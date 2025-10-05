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

  // AA view for the whole module
  auto AAView = AliasAnalysisView::create(IRDB, /*WithGlobals*/ true, AATy);

  std::unordered_set<const llvm::Function *> AnalyzedFunctions;
  std::unique_ptr<phasar::DirectAliasComputer> Computer;

  auto *Mod = IRDB.getModule();
  const auto &DL = Mod->getDataLayout();

  auto TStart = std::chrono::high_resolution_clock::now();

  for (llvm::Function &F : *Mod) {
    if (F.isDeclaration())
      continue;

    // View bound to this function (used for alias queries in your heuristics)
    auto FAV = AAView->getAAResults(&F);

    // Direct alias edges (your existing collector)
    Computer = std::make_unique<phasar::DirectAliasComputer>(
        FAV, AnalyzedFunctions,
        [&](const llvm::Value *A, const llvm::Value *B, AliasKind Kind) {
          R.Graph->addAlias(A, B, Kind);
        },
        [&](const llvm::Value *Ptr) { R.Graph->ensureExists(Ptr); });

    Computer->computeDirectAliases(&F);
    R.TotalPointers += Computer->getTotalPointerCount();

    // NEW: Store→Load promotion (correct relation: loaded pointer value == stored pointer value),
    // using same-BB fast path clobber checks
    llvm::DominatorTree DT(F);
    R.Graph->promoteByStoreLoadXBBStrict(F, *R.Graph, FAV, DL, DT);
  }

  // Structural must-alias edges (same base + const offset; zero-index GEPs)
  R.Graph->addHeuristicMustAliasEdges(DL);

  // NEW: Frequency-based May→Must, with degree-aware threshold + base+offset corroboration.
  // Tune alpha/hardMin if needed.
  R.Graph->promoteFrequentMayAliases(DL, /*alpha=*/0.5, /*hardMin=*/3);

  // Keep any additional custom heuristics
  HeuristicUtils::applyAllHeuristics(*R.Graph);

  // Build clusters from MustAlias edges
  R.Clusters = std::make_unique<AliasClusterInfo>(*R.Graph);

  auto TEnd = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> Secs = TEnd - TStart;
  llvm::outs() << "[AliasPipeline] Built graph + clusters in " << Secs.count()
               << "s, total pointers: " << R.TotalPointers << "\n";

  return R;
}

} // namespace psr
