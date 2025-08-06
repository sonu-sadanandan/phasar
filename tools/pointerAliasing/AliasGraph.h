#ifndef PHASAR_ALIASGRAPH_H
#define PHASAR_ALIASGRAPH_H

#include <boost/functional/hash.hpp>
#include "phasar/PhasarLLVM/Utils/LLVMShorthands.h"
#include "llvm/Analysis/ValueTracking.h"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <queue>
#include <string>
#include <fstream>
#include "llvm/IR/Value.h"
#include "DirectAliasComputer.h"

using Pointer = const llvm::Value*;

struct AliasEdge {
    Pointer target;
    AliasKind kind;
};

struct PointerPairHash {
    std::size_t operator()(const std::pair<const llvm::Value *, const llvm::Value *> &P) const {
        return llvm::hash_combine(P.first, P.second);
    }
};

using AliasMap = std::unordered_map<Pointer, std::vector<AliasEdge>>;

class AliasGraph {
public:
    AliasMap aliasMap;

    void recordMayAliasFrequency(Pointer A, Pointer B) {
        if (A == B) return;

        auto canonical = (A < B) ? std::make_pair(A, B) : std::make_pair(B, A);
        MayAliasFrequency[canonical]++;
    }

    void addAlias(Pointer a, Pointer b, AliasKind kind) {
        if (a == b) return;
        if (kind == AliasKind::MayAlias) {
            recordMayAliasFrequency(a, b);
        }
        aliasMap[a].push_back({b, kind});
        aliasMap[b].push_back({a, kind});
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

    void promoteFrequentMayAliases(int threshold = 3) {
        for (const auto &[pair, count] : MayAliasFrequency) {
            if (count >= threshold) {
                addAlias(pair.first, pair.second, AliasKind::MustAlias);
                llvm::outs() << "[Promoted by Frequency] " << getNodeName(pair.first)
                             << " <-> " << getNodeName(pair.second)
                             << " [count = " << count << "]\n";
            }
        }
    }

    void addHeuristicMustAliasEdges(const llvm::DataLayout &DL) {
        for (auto it1 = aliasMap.begin(); it1 != aliasMap.end(); ++it1) {
            const auto *Ptr1 = it1->first;
            auto *UO1 = llvm::getUnderlyingObject(Ptr1);

            auto it2 = it1;
            ++it2;
            for (; it2 != aliasMap.end(); ++it2) {
                const auto *Ptr2 = it1->first;
                auto *UO2 = llvm::getUnderlyingObject(Ptr2);

                if (UO1 == UO2) {
                    auto getOffset = [&](const llvm::Value *V) -> llvm::Optional<uint64_t> {
                        if (auto *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(V)) {
                            llvm::SmallVector<llvm::Value *, 4> Indices(GEP->idx_begin(), GEP->idx_end());
                            return DL.getIndexedOffsetInType(GEP->getSourceElementType(), Indices);
                        }
                        return 0;
                    };
                    auto Offset1 = getOffset(Ptr1);
                    auto Offset2 = getOffset(Ptr2);
                    if (Offset1 && Offset2 && *Offset1 == *Offset2) {
                        addAlias(Ptr1, Ptr2, AliasKind::MustAlias);
                        continue;
                    }
                }

                if (auto *GA = llvm::dyn_cast<llvm::GetElementPtrInst>(Ptr1)) {
                    if (GA->hasAllZeroIndices()) {
                        if (auto *GB = llvm::dyn_cast<llvm::GetElementPtrInst>(Ptr2)) {
                            if (GB->hasAllZeroIndices() && GA->getPointerOperand() == GB->getPointerOperand()) {
                                addAlias(Ptr1, Ptr2, AliasKind::MustAlias);
                                continue;
                            }
                        }
                    }
                }
            }
        }
    }

    void promoteByStoreLoad(llvm::Function &F, AliasGraph &Graph, psr::FunctionAliasView &FAV) {
        
        for (auto &I : instructions(F)) {
            auto *Store = llvm::dyn_cast<llvm::StoreInst>(&I);
            if (!Store) continue;

            const llvm::Value *StoredVal = Store->getValueOperand();
            const llvm::Value *StorePtr = Store->getPointerOperand();

            for (auto &J : instructions(F)) {
                auto *Load = llvm::dyn_cast<llvm::LoadInst>(&J);
                if (!Load) continue;

                const llvm::Value *LoadPtr = Load->getPointerOperand();

                // Check if the loaded pointer is the same as stored to
                if (!Graph.isMayAlias(StorePtr, LoadPtr)) continue;

                // Ensure load is AFTER store
                if (!Store->comesBefore(Load)) continue;

                bool interfered = false;
                for (auto &K : instructions(F)) {
                    if (&K == Store || &K == Load) continue;

                    if (!Store->comesBefore(&K) || !(&K)->comesBefore(Load))
                        continue; // Only care about instructions between store and load

                    // If there's another store in between
                    if (auto *OtherStore = llvm::dyn_cast<llvm::StoreInst>(&K)) {
                        const llvm::Value *OtherPtr = OtherStore->getPointerOperand();
                        // If this store may alias with StorePtr, it's unsafe
                        if (FAV.alias(StorePtr, OtherPtr, F.getParent()->getDataLayout()) != psr::AliasResult::NoAlias) {
                            interfered = true;
                            break;
                        }
                    }
                }

                if (!interfered) {
                    llvm::outs() << "Promoting: " << phasar::getReadableName(StoredVal)
                                << " <-> " << phasar::getReadableName(StorePtr)
                                << " [Load: " << phasar::getReadableName(Load) << "]\n";
                    Graph.addAlias(StoredVal, StorePtr, AliasKind::MustAlias);
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
        logAliasMap(aliasMap, "/workspaces/phasar/build/aliasMap_log.txt");
        std::vector<std::unordered_set<Pointer>> clusters;
        std::unordered_set<Pointer> visited;
        std::queue<Pointer> q;

        // Only seed clusters from real LLVM pointers, not our synthetic names
        for (const auto& [ptr, _] : aliasMap) {
            if (visited.count(ptr))
                continue;

            std::unordered_set<Pointer> cluster;
            q.push(ptr);
            visited.insert(ptr);

            while (!q.empty()) {
                Pointer cur = q.front(); q.pop();
                cluster.insert(cur);
                // Traverse only MustAlias edges
                for (const auto& edge : aliasMap.at(cur)) {
                    if (edge.kind != AliasKind::MustAlias)
                        continue;
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


    void printAliasClusters(const std::vector<std::unordered_set<Pointer>> &clusters) const {
        llvm::outs() << "\nAlias Clusters (MustAlias-based):\n";
        if (clusters.empty()) {
            llvm::outs() << "  No clusters found.\n";
            return;
        }
        int clusterId = 0;
        for (const auto& cluster : clusters) {
            llvm::outs() << "  Cluster " << clusterId++ << ": { ";
            for (const auto &ptr : cluster) {
                llvm::outs() << getNodeName(ptr) << ", ";
            }
            llvm::outs() << "}\n";
        }
    }

/*    void printAliasClusters(const std::vector<std::unordered_set<Pointer>> &clusters) const {
        llvm::outs() << "\nAlias Clusters (MustAlias-based):\n";
        if (clusters.empty()) {
            llvm::outs() << "  No clusters found.\n";
            return;
        }
        int clusterId = 0;
        for (const auto& cluster : clusters) {
            llvm::outs() << "  Cluster " << clusterId++ << ": { ";
            for (const auto &ptr : cluster) {
                if (ptr)
                    ptr->print(llvm::outs());
                else
                    llvm::outs() << "nullptr";
                llvm::outs() << ", ";
            }
            llvm::outs() << "}\n";
        }
    } */

private:
    std::unordered_map<std::pair<const llvm::Value *, const llvm::Value *>, int, PointerPairHash> MayAliasFrequency;
    std::string getNodeName(const Pointer &P) const {
        return phasar::getReadableName(P);
    }
};

#endif