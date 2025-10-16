#include "phasar/PhasarLLVM/Pointer/AliasClusterInfo.h"
#include "phasar/PhasarLLVM/Pointer/AliasGraph.h"
#include "phasar/PhasarLLVM/Utils/LLVMShorthands.h"
#include "phasar/PhasarLLVM/Pointer/AliasCommon.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <unordered_map>

using namespace psr;

namespace {

// Kind ranking: lower is “earlier” in total order
static inline unsigned kindRank(const llvm::Value *V) {
  using namespace llvm;
  if (isa<AllocaInst>(V)) return 0;
  if (isa<Argument>(V))   return 1;
  if (isa<GlobalValue>(V))return 2;
  if (isa<Instruction>(V))return 3;
  return 4; // constants, constant expr, etc.
}

struct InstIndexer {
  // Stable indices for instructions
  std::unordered_map<const llvm::Instruction*, unsigned> Idx;

  void indexFunction(const llvm::Function &F) {
    if (F.isDeclaration()) return;
    unsigned counter = 0;
    for (const auto &BB : F) {
      for (const auto &I : BB) {
        Idx.emplace(&I, counter++);
      }
    }
  }

  unsigned get(const llvm::Instruction *I) const {
    auto it = Idx.find(I);
    return (it == Idx.end()) ? UINT_MAX : it->second;
  }
};

struct ValueLess {
  const InstIndexer &Index;

  bool operator()(const llvm::Value *A, const llvm::Value *B) const {
    unsigned kA = kindRank(A), kB = kindRank(B);
    if (kA != kB) return kA < kB;

    // Same kind: refine
    if (auto *GA = llvm::dyn_cast<llvm::GlobalValue>(A)) {
      auto *GB = llvm::cast<llvm::GlobalValue>(B);
      return GA->getName() < GB->getName();
    }
    if (auto *AA = llvm::dyn_cast<llvm::Argument>(A)) {
      auto *AB = llvm::cast<llvm::Argument>(B);
      // function name, then arg no
      if (AA->getParent()->getName() != AB->getParent()->getName())
        return AA->getParent()->getName() < AB->getParent()->getName();
      return AA->getArgNo() < AB->getArgNo();
    }
    if (auto *IA = llvm::dyn_cast<llvm::Instruction>(A)) {
      auto *IB = llvm::cast<llvm::Instruction>(B);
      // function name first to be robust across module layouts
      if (IA->getFunction()->getName() != IB->getFunction()->getName())
        return IA->getFunction()->getName() < IB->getFunction()->getName();
      // then stable per-function instruction index
      return Index.get(IA) < Index.get(IB);
    }

    // Fallback: readable name as last option (constants etc.)
    return phasar::getReadableName(A) < phasar::getReadableName(B);
  }
};

} // namespace

AliasClusterInfo::AliasClusterInfo(const AliasGraph &Graph) {
  auto Clusters = Graph.computeAliasClusters();

  // Pre-index all functions once for deterministic instruction order
  InstIndexer indexer;
  // Walk all members to discover functions to index
  for (const auto &C : Clusters) {
    for (auto *V : C) {
      if (auto *I = llvm::dyn_cast<llvm::Instruction>(V)) {
        indexer.indexFunction(*I->getFunction());
      } else if (auto *A = llvm::dyn_cast<llvm::Argument>(V)) {
        indexer.indexFunction(*A->getParent());
      }
    }
  }

  ValueLess less{indexer};

  for (const auto &Cluster : Clusters) {
    if (Cluster.empty())
      continue;

    // pick rep deterministically
    Pointer Rep = *std::min_element(Cluster.begin(), Cluster.end(), less);

    RepresentativeToCluster[Rep] = Cluster; // optional: you could also store a sorted vector

    for (Pointer P : Cluster) {
      PointerToRepresentative[P] = Rep;
    }
  }
}

bool AliasClusterInfo::hasClusterFor(Pointer Ptr) const {
  return PointerToRepresentative.count(Ptr);
}

AliasClusterInfo::Pointer
AliasClusterInfo::getRepresentative(Pointer Ptr) const {
  auto It = PointerToRepresentative.find(Ptr);
  return (It != PointerToRepresentative.end()) ? It->second : Ptr;
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
