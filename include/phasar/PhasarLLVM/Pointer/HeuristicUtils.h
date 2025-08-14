#pragma once
#include "phasar/PhasarLLVM/Pointer/AliasGraph.h"

namespace HeuristicUtils {

  // All heuristic function declarations
  void applyIsolatedMayAliasHeuristic(psr::AliasGraph &graph);
  void applySharedMustAliasHeuristic(psr::AliasGraph &graph);

  // Combined interface
  void applyAllHeuristics(psr::AliasGraph &graph);
}
