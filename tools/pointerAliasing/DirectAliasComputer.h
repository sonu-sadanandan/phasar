#ifndef PHASAR_DIRECTALIASCOMPUTER_H
#define PHASAR_DIRECTALIASCOMPUTER_H

#include "phasar/PhasarLLVM/Pointer/AliasAnalysisView.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>
#include <unordered_set>
#include <fstream>
#include "AliasCommon.h"

namespace phasar {

    class DirectAliasComputer {
      public:
        DirectAliasComputer(psr::FunctionAliasView AA,
                                std::unordered_set<const llvm::Function *> &AnalyzedFunctions,
                                std::function<void(const llvm::Value *, const llvm::Value *, AliasKind)> addAlias,
                            std::function<void(const llvm::Value *)> ensureNode)
            : AA_(AA), AnalyzedFunctions_(AnalyzedFunctions), addAlias_(addAlias), ensureNode_(ensureNode) {}

        void computeDirectAliases(llvm::Function *F) {
            if (!F || F->isDeclaration()) {
                return;
            }

            // Check if we already analyzed the function
            if (auto [Unused, Inserted] = AnalyzedFunctions_.insert(F); !Inserted) {
                return;
            }

            std::vector<const llvm::Value *> Pointers;
            llvm::DenseSet<const llvm::Value *> UsedGlobals;
            const auto &DL = F->getParent()->getDataLayout();

            for (auto &Inst : llvm::instructions(F)) {
                if (Inst.getType()->isPointerTy()) {
                    Pointers.push_back(&Inst);
                }

                for (auto &Op : Inst.operands()) {
                    if (llvm::isa<llvm::GlobalVariable>(Op)) {
                        UsedGlobals.insert(Op);
                    }
                }
            }

            for (auto &Arg : F->args()) {
                if (Arg.getType()->isPointerTy()) {
                    Pointers.push_back(&Arg);
                }
            }

            for (const llvm::Value *Glob : UsedGlobals) {
                Pointers.push_back(Glob);
            }

            TotalPointerCount += Pointers.size();

            // Check aliasing between all pairs of pointers
            std::ofstream AliasLog("/workspaces/phasar/build/alias_log.txt");
            for (size_t i = 0; i < Pointers.size(); ++i) {
                for (size_t j = i + 1; j < Pointers.size(); ++j) {
                    const llvm::Value *A = Pointers[i];
                    const llvm::Value *B = Pointers[j];

                    psr::AliasResult Result = AA_.alias(A, B, DL); 
                    AliasLog << "Checking alias between: "
                    << getReadableName(A) << " and " << getReadableName(B)
                    << " => ";
                    switch (Result) {
                        case psr::AliasResult::NoAlias:
                            AliasLog << "NoAlias";
                            break;
                        case psr::AliasResult::MayAlias:
                            AliasLog << "MayAlias";
                            break;
                        case psr::AliasResult::MustAlias:
                            AliasLog << "MustAlias";
                            break;
                        case psr::AliasResult::PartialAlias:
                            AliasLog << "PartialAlias";
                            break;
                    }

                    AliasLog << "\n"; 
                    if (Result != psr::AliasResult::NoAlias) { 
                        AliasKind Kind = (Result == psr::AliasResult::MustAlias) ? AliasKind::MustAlias: AliasKind::MayAlias;
                        addAlias_(A, B, Kind);
                    }
                }
            }
            AliasLog.close();

            // Ensure all pointers exist as singleton nodes if they have no aliases
            for (const auto *Ptr : Pointers) {
                ensureNode_(Ptr);
            }
        }

        size_t getTotalPointerCount() const { return TotalPointerCount; }

      private:
        psr::FunctionAliasView AA_;
        std::unordered_set<const llvm::Function *> &AnalyzedFunctions_;
        std::function<void(const llvm::Value *, const llvm::Value *, AliasKind)> addAlias_;
        std::function<void(const llvm::Value *)> ensureNode_;

        size_t TotalPointerCount = 0;
    };
}

#endif