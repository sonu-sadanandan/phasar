#ifndef PHASAR_ALIASGRAPH_H
#define PHASAR_ALIASGRAPH_H

#include <unordered_map>
#include <vector>
#include <unordered_set>
#include <queue>
#include "llvm/IR/Value.h"
#include "DirectAliasComputer.h"

using Pointer = const llvm::Value*;

enum class AliasKind { MustAlias, MayAlias };

struct AliasEdge {
    Pointer target;
    AliasKind kind;
};

using AliasMap = std::unordered_map<Pointer, std::vector<AliasEdge>>;

class AliasGraph {
public:
    AliasMap aliasMap;

    void addAlias(Pointer a, Pointer b, AliasKind kind) {
        // llvm::outs() << " [Kind: ";
        // if (kind == AliasKind::MustAlias)
        // llvm::outs() << "MustAlias \n";
        // else
        // llvm::outs() << "MayAlias \n";
        aliasMap[a].push_back({b, kind});
        aliasMap[b].push_back({a, kind});
    }

    std::vector<std::unordered_set<Pointer>> computeAliasClusters(
        const std::unordered_map<Pointer, std::vector<AliasEdge>>& aliasMap) const{
    
        std::unordered_set<Pointer> visited;
        std::vector<std::unordered_set<Pointer>> clusters;
    
        for (const auto& [node, edges] : aliasMap) {
            if (visited.count(node)) continue;
    
            std::unordered_set<Pointer> cluster;
            std::queue<Pointer> q;
            q.push(node);
            visited.insert(node);
    
            while (!q.empty()) {
                Pointer current = q.front();
                q.pop();
                cluster.insert(current);
    
                for (const auto& edge : aliasMap.at(current)) {
                    const Pointer& neighbor = edge.target;
                    if (!visited.count(neighbor)) {
                        visited.insert(neighbor);
                        q.push(neighbor);
                    }
                }
            }
            clusters.push_back(std::move(cluster));
        }
    
        // Check for orphan nodes (e.g., ptr) not present in aliasMap keys
        std::unordered_set<Pointer> allSeen;
        for (const auto& cluster : clusters) {
            allSeen.insert(cluster.begin(), cluster.end());
        }
    
        for (const auto& [node, _] : aliasMap) {
            for (const auto& edge : aliasMap.at(node)) {
                if (!allSeen.count(edge.target)) {
                    clusters.push_back({edge.target});
                    allSeen.insert(edge.target);
                }
            }
            if (!allSeen.count(node)) {
                clusters.push_back({node});
                allSeen.insert(node);
            }
        }
    
        return clusters;
    }  
    
    void printAliasClusters() const {
        llvm::outs() << "\nAlias Clusters:\n";
    
        // Compute the clusters using the current aliasMap
        auto clusters = computeAliasClusters(aliasMap);
    
        int clusterId = 0;
        for (const auto& cluster : clusters) {
            llvm::outs() << "  Cluster " << clusterId++ << ": { ";
            for (const auto* ptr : cluster) {
                if (ptr->hasName()) {
                    llvm::outs() << ptr->getName() << " ";
                } else {
                    llvm::outs() << "[";
                    ptr->print(llvm::outs());
                    llvm::outs() << "] ";
                }
            }
            llvm::outs() << "}\n";
        }
    }    

    void printAliasMap() const {
        llvm::outs() << "AliasMap contents:\n";
        for (const auto &[source, edges] : aliasMap) {
            llvm::outs() << "  ";
            if (source->hasName()) {
                llvm::outs() << source->getName();
            } else {
                llvm::outs() << "[";
                source->print(llvm::outs());
                llvm::outs() << "]";
            }
    
            llvm::outs() << " -> ";
    
            for (const auto &edge : edges) {
                if (edge.target->hasName()) {
                    llvm::outs() << edge.target->getName();
                } else {
                    llvm::outs() << "[";
                    edge.target->print(llvm::outs());
                    llvm::outs() << "]";
                }
    
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
