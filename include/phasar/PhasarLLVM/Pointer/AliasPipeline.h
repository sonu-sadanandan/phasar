#pragma once
#include <memory>
#include "phasar/PhasarLLVM/Pointer/AliasGraph.h"
#include "phasar/PhasarLLVM/Pointer/AliasClusterInfo.h"
#include "phasar/PhasarLLVM/DB/LLVMProjectIRDB.h"
#include "phasar/Pointer/AliasAnalysisType.h"
#include "phasar/PhasarLLVM/Pointer/AliasAnalysisView.h"

namespace psr {

struct AliasPipelineResult {
  std::unique_ptr<AliasGraph> Graph;
  std::unique_ptr<AliasClusterInfo> Clusters;
  std::size_t TotalPointers = 0;
};

// Build the alias graph and clusters for the whole module in IRDB
// using the chosen AA type (e.g., CFLAnders).
AliasPipelineResult buildAliasClusters(LLVMProjectIRDB &IRDB,
                                       AliasAnalysisType AATy);

} // namespace psr
