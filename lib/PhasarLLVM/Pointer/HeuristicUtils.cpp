#include "phasar/PhasarLLVM/Pointer/HeuristicUtils.h"

namespace HeuristicUtils {

    void applyIsolatedMayAliasHeuristic(psr::AliasGraph &Graph) {
        for (const auto &entry : Graph.aliasMap) {
            const psr::Pointer &A = entry.first;
            const auto &edges = entry.second;

            psr::Pointer candidate;
            bool found = false;
            for (const auto &edge : edges) {
                if (edge.kind != AliasKind::MayAlias) continue;
                if (found) {
                    candidate = {};
                    break; // More than one MayAlias, not isolated
                }
                candidate = edge.target;
                found = true;
            }

            if (!found) continue;

            auto it = Graph.aliasMap.find(candidate);
            if (it == Graph.aliasMap.end())
                continue; // skip invalid or missing candidate

            const auto &edgesB = it->second;
            size_t symmetricCount = 0;
            for (const auto &e : edgesB) {
                if (e.kind == AliasKind::MayAlias && e.target == A) {
                    symmetricCount++;
                }
            }

            if (symmetricCount == 1) {
                size_t mayB = 0;
                for (const auto &e : edgesB) {
                    if (e.kind == AliasKind::MayAlias) {
                        mayB++;
                    }
                }

                if (mayB == 1) {
                    Graph.addAlias(A, candidate, AliasKind::MustAlias);
                }
            }
        }
    }

    void applySharedMustAliasHeuristic(psr::AliasGraph &Graph) {
        for (const auto &entryA : Graph.aliasMap) {
            const psr::Pointer &A = entryA.first;
            const auto &edgesA = entryA.second;

            for (const auto &entryB : Graph.aliasMap) {
                const psr::Pointer &B = entryB.first;
                const auto &edgesB = entryB.second;

                if (A == B) continue;
                if (!Graph.isMayAlias(A, B)) continue;

                std::unordered_set<psr::Pointer> mustsA, mustsB;
                for (const auto &edge : edgesA) {
                    if (edge.kind == AliasKind::MustAlias)
                        mustsA.insert(edge.target);
                }
                for (const auto &edge : edgesB) {
                    if (edge.kind == AliasKind::MustAlias)
                        mustsB.insert(edge.target);
                }

                for (const auto &common : mustsA) {
                    if (mustsB.count(common)) {
                        Graph.addAlias(A, B, AliasKind::MustAlias);
                        break;
                    }
                }
            }
        }
    }

    void applyAllHeuristics(psr::AliasGraph &graph) {
        applyIsolatedMayAliasHeuristic(graph);
        applySharedMustAliasHeuristic(graph);
    }

}
