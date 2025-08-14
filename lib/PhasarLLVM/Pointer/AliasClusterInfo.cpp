#include "phasar/PhasarLLVM/Pointer/AliasClusterInfo.h"
#include "phasar/PhasarLLVM/Utils/LLVMShorthands.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>

using namespace psr;

AliasClusterInfo::AliasClusterInfo(const AliasGraph &Graph) {
  auto Clusters = Graph.computeAliasClusters();

  for (const auto &Cluster : Clusters) {
    if (Cluster.empty())
      continue;

    Pointer Rep = selectRepresentative(Cluster);
    RepresentativeToCluster[Rep] = Cluster;

    for (Pointer P : Cluster) {
      PointerToRepresentative[P] = Rep;
    }
  }
}

bool AliasClusterInfo::hasClusterFor(Pointer Ptr) const {
  return PointerToRepresentative.count(Ptr);
}

AliasClusterInfo::Pointer AliasClusterInfo::getRepresentative(Pointer Ptr) const {
  auto It = PointerToRepresentative.find(Ptr);
  if (It != PointerToRepresentative.end()) {
    return It->second;
  }
  return Ptr;
}

const std::unordered_set<AliasClusterInfo::Pointer> &
AliasClusterInfo::getClusterMembers(Pointer Rep) const {
  static const std::unordered_set<Pointer> Empty;
  auto It = RepresentativeToCluster.find(Rep);
  return It != RepresentativeToCluster.end() ? It->second : Empty;
}

const std::unordered_map<AliasClusterInfo::Pointer, AliasClusterInfo::Pointer> &
AliasClusterInfo::getPointerToRepMap() const {
  return PointerToRepresentative;
}

AliasClusterInfo::Pointer
AliasClusterInfo::selectRepresentative(const std::unordered_set<Pointer> &Cluster) const {
  return *std::min_element(Cluster.begin(), Cluster.end(),
    [](Pointer A, Pointer B) {
      return phasar::getReadableName(A) < phasar::getReadableName(B);
    });
}
