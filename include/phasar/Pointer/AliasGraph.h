#ifndef PHASAR_ALIASGRAPH_H
#define PHASAR_ALIASGRAPH_H

#include "phasar/PhasarLLVM/Utils/LLVMShorthands.h"

#include <unordered_map>
#include <vector>
#include <unordered_set>
#include <queue>
#include "llvm/IR/Value.h"
#include "DirectAliasComputer.h"

using Pointer = const llvm::Value*;

struct AliasEdge {
    Pointer target;
    AliasKind kind;
};

using AliasMap = std::unordered_map<Pointer, std::vector<AliasEdge>>;

class AliasGraph {
public:
    AliasMap aliasMap;

    void addAlias(Pointer a, Pointer b, AliasKind kind) {
        if (!b) return; // skip if b is null (singleton insert handled separately)
        aliasMap[a].push_back({b, kind});
        aliasMap[b].push_back({a, kind});
    }

    void ensureExists(Pointer ptr) {
        aliasMap.try_emplace(ptr); // insert empty vector if not already present
    }

    // Compute clusters using only MustAlias edges
    std::vector<std::unordered_set<Pointer>> computeAliasClusters() const {
        std::vector<std::unordered_set<Pointer>> clusters;
        std::unordered_set<Pointer> visited;
        // BFS over MustAlias edges
        for (const auto& [ptr, edges] : aliasMap) {
            if (visited.count(ptr)) continue;
            std::unordered_set<Pointer> cluster;
            std::queue<Pointer> q;
            q.push(ptr);
            visited.insert(ptr);
            while (!q.empty()) {
                Pointer cur = q.front(); q.pop();
                cluster.insert(cur);
                auto it = aliasMap.find(cur);
                if (it == aliasMap.end()) continue;
                for (const auto& edge : it->second) {
                    if (edge.kind == AliasKind::MustAlias) {
                        Pointer nb = edge.target;
                        if (!visited.count(nb)) {
                            visited.insert(nb);
                            q.push(nb);
                        }
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
            for (const auto* ptr : cluster) {
                llvm::outs() << phasar::getReadableName(ptr) << ", ";
            }
            llvm::outs() << "}\n";
        }
    }

    void printAliasMap() const {
        llvm::outs() << "AliasMap contents:\n";
        for (const auto &[source, edges] : aliasMap) {
            llvm::outs() << "  ";
            llvm::outs() << phasar::getReadableName(source);
    
            llvm::outs() << " -> ";
    
            for (const auto &edge : edges) {
                llvm::outs() << phasar::getReadableName(edge.target);
    
                llvm::outs() << " [";
                if (edge.kind == AliasKind::MustAlias)
                    llvm::outs() << "MustAlias";
                else
                    llvm::outs() << "MayAlias";
                llvm::outs() << "], ";
            }
            llvm::outs() << "\n";
        }
    }    
};

#endif
