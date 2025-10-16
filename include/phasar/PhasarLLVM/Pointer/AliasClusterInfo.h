#ifndef PHASAR_ALIASCLUSTERINFO_H
#define PHASAR_ALIASCLUSTERINFO_H

#include <unordered_map>
#include <unordered_set>

namespace llvm {
class Value;
} // namespace llvm

namespace psr {
class AliasGraph; 

/// Frozen, deterministic canonicalization of MustAlias clusters:
/// - builds clusters from the MustAlias-only subgraph
/// - picks a stable representative per cluster (deterministic total order)
/// - exposes O(1) pointer -> representative queries
class AliasClusterInfo {
public:
  using Pointer = const llvm::Value *;
  explicit AliasClusterInfo(const AliasGraph &Graph);
  bool hasClusterFor(Pointer Ptr) const;
  Pointer getRepresentative(Pointer Ptr) const;

  const std::unordered_set<Pointer> &getClusterMembers(Pointer Rep) const;
  const std::unordered_map<Pointer, Pointer> &getPointerToRepMap() const;

private:
  // Frozen maps after build:
  std::unordered_map<Pointer, Pointer> PointerToRepresentative;
  std::unordered_map<Pointer, std::unordered_set<Pointer>> RepresentativeToCluster;
};

} // namespace psr

#endif 
