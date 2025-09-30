#pragma once
#include "../AliasGraph.h"

namespace HeuristicUtils {

  // All heuristic function declarations
  void applyIsolatedMayAliasHeuristic(AliasGraph &graph);
  void applySharedMustAliasHeuristic(AliasGraph &graph);

  // Combined interface
  void applyAllHeuristics(AliasGraph &graph);
}
