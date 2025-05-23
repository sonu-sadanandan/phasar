#ifndef PHASAR_DIRECTALIASCOMPUTER_H
#define PHASAR_DIRECTALIASCOMPUTER_H

#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include "AliasGraph.h"

#include <vector>
#include <unordered_set>

namespace phasar {

    class DirectAliasComputer {
      public:
        DirectAliasComputer(llvm::AAResults &AA,
                                std::unordered_set<const llvm::Function *> &AnalyzedFunctions,
                                std::function<void(const llvm::Value *, const llvm::Value *, AliasKind)> addAlias)
            : AA_(AA), AnalyzedFunctions_(AnalyzedFunctions), addAlias_(addAlias) {}

        void computeDirectAliases(llvm::Function *F) {
            if (!F || F->isDeclaration()) {
                return;
            }

            // Check if we already analyzed the function
            if (auto [Unused, Inserted] = AnalyzedFunctions_.insert(F); !Inserted) {
                return;
            }

            llvm::outs() << "Computing direct aliases for function: " << F->getName() << "\n";

            std::vector<const llvm::Value *> Pointers;
            llvm::DenseSet<const llvm::Value *> UsedGlobals;

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

            llvm::outs() << "List of pointers collected for alias analysis:\n";
            for (const auto *Ptr : Pointers) {
                llvm::outs() << "  - ";
                if (Ptr->hasName()) {
                    llvm::outs() << Ptr->getName();
                } else {
                    Ptr->print(llvm::outs());
                }
                llvm::outs() << " [ Type: ";
                Ptr->getType()->print(llvm::outs());
                llvm::outs() << "]\n";
            }

            // Check aliasing between all pairs of pointers
            for (size_t i = 0; i < Pointers.size(); ++i) {
                for (size_t j = i + 1; j < Pointers.size(); ++j) {
                    const llvm::Value *A = Pointers[i];
                    const llvm::Value *B = Pointers[j];

                    llvm::outs() << "Checking alias between: ";
                    if (A->hasName())
                        llvm::outs() << A->getName();
                    else
                        A->print(llvm::outs());
                    llvm::outs() << " and ";
                    if (B->hasName())
                        llvm::outs() << B->getName();
                    else
                        B->print(llvm::outs());
                    llvm::outs() << "\n";

                    llvm::AliasResult Result = AA_.alias(A, B);  
                    llvm::outs() << "Alias result: " << Result << "\n";
                    if (Result != llvm::AliasResult::NoAlias) { 
                        AliasKind Kind = (Result == llvm::AliasResult::MustAlias) ? AliasKind::MustAlias: AliasKind::MayAlias;
                        addAlias_(A, B, Kind);
                    }
                }
            }
        }

      private:
        llvm::AAResults &AA_;
        std::unordered_set<const llvm::Function *> &AnalyzedFunctions_;
        std::function<void(const llvm::Value *, const llvm::Value *, AliasKind)> addAlias_;
    };
}

#endif // PHASAR_DIRECTALIASCOMPUTER_H