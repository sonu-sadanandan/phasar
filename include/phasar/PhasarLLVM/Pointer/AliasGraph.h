#ifndef PHASAR_ALIASGRAPH_H
#define PHASAR_ALIASGRAPH_H

#include <boost/functional/hash.hpp>
#include "phasar/PhasarLLVM/Utils/LLVMShorthands.h"
#include "phasar/PhasarLLVM/Pointer/AliasAnalysisView.h"
#include "phasar/PhasarLLVM/Pointer/AliasCommon.h"
#include "phasar/Pointer/AliasResult.h"

#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Analysis/MemoryLocation.h"
#include "llvm/IR/Dominators.h" 

#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <queue>
#include <string>
#include <fstream>

#include "llvm/IR/Value.h"

namespace psr {

using Pointer = const llvm::Value*;

struct AliasEdge {
  Pointer target;
  AliasKind kind;
};

// ---------- Pair canonicalization & origin tracking ----------

struct PairKey {
  const llvm::Value* X;
  const llvm::Value* Y;
  bool operator==(const PairKey& o) const { return X == o.X && Y == o.Y; }
};
struct PairKeyHash {
  std::size_t operator()(const PairKey& k) const {
    return llvm::hash_combine(k.X, k.Y);
  }
};

struct OriginKey {
  const llvm::Function* F;
  const llvm::Instruction* I; // use callsite or exact inst for dedup
  bool operator==(const OriginKey& o) const { return F == o.F && I == o.I; }
};
struct OriginKeyHash {
  std::size_t operator()(const OriginKey& o) const {
    return llvm::hash_combine(o.F, o.I);
  }
};

struct PointerPairHash {
  std::size_t operator()(const std::pair<const llvm::Value*, const llvm::Value*>& P) const {
    return llvm::hash_combine(P.first, P.second);
  }
};

using AliasMap = std::unordered_map<Pointer, std::vector<AliasEdge>>;

class AliasGraph {
public:
  AliasMap aliasMap;

  // --- Compatibility: it forwards to origin-aware one with null origin.
  void recordMayAliasFrequency(Pointer A, Pointer B) {
    recordMayAliasFrequency(A, B, /*F*/ nullptr, /*I*/ nullptr);
  }

  //origin-deduped frequency recorder
  void recordMayAliasFrequency(Pointer A, Pointer B,
                               const llvm::Function* F,
                               const llvm::Instruction* I) {
    if (A == B) return;
    auto key = canonPair(A, B);
    OriginKey ok{F, I};
    auto& seen = SeenOrigins[key];
    if (seen.insert(ok).second) {
      MayAliasCount[key] += 1;
    }
  }

  // Optional: allow callers to veto future promotion on hard NoAlias evidence
  void recordNoAlias(Pointer A, Pointer B) {
    if (A == B) return;
    NoAliasBlocklist.insert(canonPair(A, B));
  }

  // Edge insertion with deduplication
  void addAlias(Pointer a, Pointer b, AliasKind kind) {
    addAliasDedup(a, b, kind);
    if (kind == AliasKind::MayAlias) {
      // When no origin is known, still count—but dedup happens at addAliasDedup for edges,
      // and frequency dedup happens per origin above when origin is provided.
      recordMayAliasFrequency(a, b, nullptr, nullptr);
    }
  }

  bool isMayAlias(const Pointer &A, const Pointer &B) const {
    auto it = aliasMap.find(A);
    if (it == aliasMap.end()) return false;
    for (const auto &e : it->second) {
      if (e.target == B && e.kind == AliasKind::MayAlias)
        return true;
    }
    return false;
  }

  void ensureExists(Pointer ptr) {
    aliasMap.try_emplace(ptr);
  }

  // --------- Improved Frequency Promotion ---------
  void promoteFrequentMayAliases(int threshold = 3) {
    for (const auto &kv : MayAliasCount) {
      const PairKey &key = kv.first;
      unsigned count = kv.second;
      if (NoAliasBlocklist.count(key)) continue;
      if (count >= static_cast<unsigned>(threshold)) {
        addAliasDedup(key.X, key.Y, AliasKind::MustAlias);
      }
    }
  }

  // Safer overload: degree-aware threshold + base+const-offset corroboration
  void promoteFrequentMayAliases(const llvm::DataLayout &DL,
                                 double alpha = 0.5, unsigned hardMin = 3) {
    for (const auto &kv : MayAliasCount) {
      const PairKey &key = kv.first;
      unsigned cnt = kv.second;
      if (NoAliasBlocklist.count(key)) continue;

      unsigned deg =
          (aliasMap.count(key.X) ? aliasMap.at(key.X).size() : 0) +
          (aliasMap.count(key.Y) ? aliasMap.at(key.Y).size() : 0);
      unsigned thr = std::max(hardMin, (unsigned)std::ceil(alpha * std::max(1u, deg)));
      if (cnt < thr) continue;

      if (!sameBaseSameConstOffset(DL, key.X, key.Y)) continue;
      addAliasDedup(key.X, key.Y, AliasKind::MustAlias);
    }
  }

  // Structural must-alias edges (base+offset equality, zero-index GEPs)
  void addHeuristicMustAliasEdges(const llvm::DataLayout &DL) {
    for (auto it1 = aliasMap.begin(); it1 != aliasMap.end(); ++it1) {
      const auto *Ptr1 = it1->first;
      auto it2 = it1; ++it2;
      for (; it2 != aliasMap.end(); ++it2) {
        const auto *Ptr2 = it2->first;

        if (sameBaseSameConstOffset(DL, Ptr1, Ptr2)) {
          addAliasDedup(Ptr1, Ptr2, AliasKind::MustAlias);
          continue;
        }

        if (auto *GA = llvm::dyn_cast<llvm::GetElementPtrInst>(Ptr1)) {
          if (GA->hasAllZeroIndices()) {
            if (auto *GB = llvm::dyn_cast<llvm::GetElementPtrInst>(Ptr2)) {
              if (GB->hasAllZeroIndices() && GA->getPointerOperand() == GB->getPointerOperand()) {
                addAliasDedup(Ptr1, Ptr2, AliasKind::MustAlias);
                continue;
              }
            }
          }
        }
      }
    }
  }

  // --------- Store→Load Promotion ---------
  // Old signature kept for compatibility.
  void promoteByStoreLoad(llvm::Function &, AliasGraph &, psr::FunctionAliasView &) {
    // Intentionally left as a no-op wrapper to avoid accidental use.
  }

  // Same-BB, DL-only, with call-arg alias filtering
  void promoteByStoreLoad(llvm::Function &F, AliasGraph &Graph,
                          psr::FunctionAliasView &FAV,
                          const llvm::DataLayout &DL) {

    auto mayAliasPtr = [&](const llvm::Value* P, const llvm::Value* Q){
      return FAV.alias(P, Q, DL) != psr::AliasResult::NoAlias;
    };

    for (auto &BB : F) {
      std::vector<llvm::Instruction*> insts;
      insts.reserve(BB.size());
      for (auto &I : BB) insts.push_back(&I);

      for (size_t i = 0; i < insts.size(); ++i) {
        auto *Store = llvm::dyn_cast<llvm::StoreInst>(insts[i]);
        if (!Store || Store->isVolatile() || Store->isAtomic()) continue;

        const llvm::Value *StorePtr  = Store->getPointerOperand();
        const llvm::Value *StoredVal = Store->getValueOperand();

        for (size_t j = i + 1; j < insts.size(); ++j) {
          auto *Load = llvm::dyn_cast<llvm::LoadInst>(insts[j]);
          if (!Load || Load->isVolatile() || Load->isAtomic()) continue;

          const llvm::Value *LoadPtr = Load->getPointerOperand();
          if (!mayAliasPtr(StorePtr, LoadPtr)) continue;

          bool interfered = false;
          for (size_t k = i + 1; k < j; ++k) {
            llvm::Instruction *K = insts[k];

            if (auto *OtherStore = llvm::dyn_cast<llvm::StoreInst>(K)) {
              const llvm::Value *OtherPtr = OtherStore->getPointerOperand();
              if (FAV.alias(StorePtr, OtherPtr, DL) != psr::AliasResult::NoAlias) {
                interfered = true; break;
              }
            } else if (auto *CB = llvm::dyn_cast<llvm::CallBase>(K)) {
              // Treat call as clobber ONLY if some pointer argument may-alias the store address.
              bool touchesStoreAddr = false;
              for (unsigned ai = 0, ae = CB->arg_size(); ai < ae; ++ai) {
                const llvm::Value *Arg = CB->getArgOperand(ai);
                if (!Arg || !Arg->getType()->isPointerTy()) continue;
                if (FAV.alias(StorePtr, Arg, DL) != psr::AliasResult::NoAlias) {
                  touchesStoreAddr = true; break;
                }
              }
              if (touchesStoreAddr) { interfered = true; break; }
            }
          }
          if (interfered) continue;

          if (StoredVal->getType()->isPointerTy() && Load->getType()->isPointerTy()) {
            Graph.addAliasDedup(Load, StoredVal, AliasKind::MustAlias);
          }
        }
      }
    }
  }

  // NEW: Cross-BB, strict & scalable: single-writer, non-escaping alloca slots.
  void promoteByStoreLoadXBBStrict(llvm::Function &F, AliasGraph &Graph,
                                   psr::FunctionAliasView &FAV,
                                   const llvm::DataLayout &DL,
                                   llvm::DominatorTree &DT) {
    // Prepass: count stores per (alloca, const offset) and detect escapes.
    struct SlotKey { const llvm::AllocaInst* A; int64_t Off; 
      bool operator==(const SlotKey& o) const { return A==o.A && Off==o.Off; } };
    struct SlotKeyHash { size_t operator()(const SlotKey& k) const {
      return llvm::hash_combine(k.A, k.Off);
    } };
    struct SlotInfo { const llvm::StoreInst* Store = nullptr; unsigned Stores = 0; };

    auto baseAllocaOf = [&](const llvm::Value* Ptr, int64_t &Off) -> const llvm::AllocaInst* {
      Off = 0;
      llvm::Value* Base = llvm::GetPointerBaseWithConstantOffset(
          const_cast<llvm::Value*>(Ptr), Off, DL);
      return llvm::dyn_cast_or_null<llvm::AllocaInst>(Base);
    };

    std::unordered_map<SlotKey, SlotInfo, SlotKeyHash> Stores;
    std::unordered_set<const llvm::AllocaInst*> Escapes;

    for (auto &BB : F) {
      for (auto &I : BB) {
        // Count stores per (alloca, offset)
        if (auto *S = llvm::dyn_cast<llvm::StoreInst>(&I)) {
          int64_t Off = 0;
          if (auto *A = baseAllocaOf(S->getPointerOperand(), Off)) {
            SlotKey K{A, Off};
            auto &SI = Stores[K];
            SI.Stores++;
            if (!SI.Store) SI.Store = S;
          }
          // Storing the address of an alloca => escape
          if (S->getValueOperand()->getType()->isPointerTy()) {
            int64_t VOff = 0;
            if (auto *VA = baseAllocaOf(S->getValueOperand(), VOff)) {
              Escapes.insert(VA);
            }
          }
        }
        // Passing address of an alloca to a call => escape
        if (auto *CB = llvm::dyn_cast<llvm::CallBase>(&I)) {
          for (unsigned ai = 0, ae = CB->arg_size(); ai < ae; ++ai) {
            const llvm::Value *Arg = CB->getArgOperand(ai);
            if (!Arg || !Arg->getType()->isPointerTy()) continue;
            int64_t AOff = 0;
            if (auto *AA = baseAllocaOf(Arg, AOff)) {
              Escapes.insert(AA);
            }
          }
        }
        // Returning address of an alloca => escape
        if (auto *RI = llvm::dyn_cast<llvm::ReturnInst>(&I)) {
          if (const llvm::Value *RV = RI->getReturnValue()) {
            if (RV->getType()->isPointerTy()) {
              int64_t ROff = 0;
              if (auto *RA = baseAllocaOf(RV, ROff)) {
                Escapes.insert(RA);
              }
            }
          }
        }
      }
    }

    // Promote loads that read from a single-writer, non-escaping slot.
    for (auto &BB : F) {
      for (auto &I : BB) {
        auto *L = llvm::dyn_cast<llvm::LoadInst>(&I);
        if (!L || L->isVolatile() || L->isAtomic()) continue;

        int64_t LOff = 0;
        const llvm::AllocaInst* LA = baseAllocaOf(L->getPointerOperand(), LOff);
        if (!LA || Escapes.count(LA)) continue;

        SlotKey LK{LA, LOff};
        auto It = Stores.find(LK);
        if (It == Stores.end()) continue;

        const SlotInfo &SI = It->second;
        if (SI.Stores != 1 || !SI.Store) continue;

        const llvm::StoreInst *S = SI.Store;

        // Address equality corroboration + dominance
        if (!sameBaseSameConstOffset(DL, S->getPointerOperand(), L->getPointerOperand()))
          continue;
        if (!DT.dominates(S, L)) continue;

        const llvm::Value *V = S->getValueOperand();
        if (V->getType()->isPointerTy() && L->getType()->isPointerTy()) {
          Graph.addAliasDedup(L, V, AliasKind::MustAlias);
        }
      }
    }
  }

  void logAliasMap(const AliasMap &Map, const std::string &filename) const {
    std::ofstream AliasMapLog(filename);
    if (!AliasMapLog) {
      llvm::errs() << "Could not open " << filename << " for writing.\n";
      return;
    }
    for (const auto &[Source, Edges] : Map) {
      AliasMapLog << "Source: " << getNodeName(Source) << "\n";
      for (const auto &Edge : Edges) {
        AliasMapLog << "  -> Target: " << getNodeName(Edge.target)
                    << ", AliasType: "
                    << (Edge.kind == AliasKind::MustAlias ? "MustAlias" : "MayAlias")
                    << "\n";
      }
    }
    AliasMapLog.close();
  }

  std::vector<std::unordered_set<Pointer>> computeAliasClusters() const {
    std::vector<std::unordered_set<Pointer>> clusters;
    std::unordered_set<Pointer> visited;
    std::queue<Pointer> q;

    for (const auto& [ptr, _] : aliasMap) {
      if (visited.count(ptr)) continue;

      std::unordered_set<Pointer> cluster;
      q.push(ptr);
      visited.insert(ptr);

      while (!q.empty()) {
        Pointer cur = q.front(); q.pop();
        cluster.insert(cur);
        // Traverse only MustAlias edges
        for (const auto& edge : aliasMap.at(cur)) {
          if (edge.kind != AliasKind::MustAlias) continue;
          Pointer nb = edge.target;
          if (!visited.count(nb)) {
            visited.insert(nb);
            q.push(nb);
          }
        }
      }
      clusters.push_back(std::move(cluster));
    }
    return clusters;
  }

private:
  // New: frequency & evidence stores
  std::unordered_map<PairKey, unsigned, PairKeyHash> MayAliasCount;
  std::unordered_map<PairKey, std::unordered_set<OriginKey, OriginKeyHash>, PairKeyHash> SeenOrigins;
  std::unordered_set<PairKey, PairKeyHash> NoAliasBlocklist;

  // Legacy map kept for compatibility
  std::unordered_map<std::pair<const llvm::Value*, const llvm::Value*>, int, PointerPairHash> MayAliasFrequencyLegacy;

  // Utilities

  static PairKey canonPair(const llvm::Value* A, const llvm::Value* B) {
    return (A < B) ? PairKey{A, B} : PairKey{B, A};
  }

  bool hasEdge(const Pointer a, const Pointer b, AliasKind k) const {
    auto it = aliasMap.find(a);
    if (it == aliasMap.end()) return false;
    for (const auto &e : it->second) {
      if (e.target == b && e.kind == k) return true;
    }
    return false;
  }

  void addAliasDedup(Pointer a, Pointer b, AliasKind kind) {
    if (a == b) return;
    if (hasEdge(a, b, kind)) return;
    aliasMap[a].push_back({b, kind});
    aliasMap[b].push_back({a, kind});
  }

  static bool sameBaseSameConstOffset(const llvm::DataLayout& DL,
                                      const llvm::Value* P,
                                      const llvm::Value* Q) {
    int64_t OffP = 0, OffQ = 0;
    llvm::Value* BaseP = llvm::GetPointerBaseWithConstantOffset(
        const_cast<llvm::Value*>(P), OffP, DL);
    llvm::Value* BaseQ = llvm::GetPointerBaseWithConstantOffset(
        const_cast<llvm::Value*>(Q), OffQ, DL);
    return BaseP && BaseQ && BaseP == BaseQ && OffP == OffQ;
  }

  std::string getNodeName(const Pointer &P) const {
    return phasar::getReadableName(P);
  }
};

} // namespace psr

#endif
