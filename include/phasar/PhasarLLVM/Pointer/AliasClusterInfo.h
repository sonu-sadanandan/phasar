#ifndef PHASAR_ALIASCLUSTERINFO_H
#define PHASAR_ALIASCLUSTERINFO_H

#include "phasar/PhasarLLVM/Pointer/AliasGraph.h"
#include "llvm/IR/Value.h"
#include <unordered_map>
#include <unordered_set>

namespace psr {
  class AliasClusterInfo {
  public:
    using Pointer = const llvm::Value *;

    explicit AliasClusterInfo(const AliasGraph &Graph);

    bool hasClusterFor(Pointer Ptr) const;

    Pointer getRepresentative(Pointer Ptr) const;

    const std::unordered_set<Pointer> &getClusterMembers(Pointer Rep) const;

    const std::unordered_map<Pointer, Pointer> &getPointerToRepMap() const;

  private:
    std::unordered_map<Pointer, Pointer> PointerToRepresentative;
    std::unordered_map<Pointer, std::unordered_set<Pointer>> RepresentativeToCluster;

    Pointer selectRepresentative(const std::unordered_set<Pointer> &Cluster) const;
  };
}

#endif
