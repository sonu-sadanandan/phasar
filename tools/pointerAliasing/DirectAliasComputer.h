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

enum class AliasKind { MustAlias, MayAlias };

namespace phasar {

    inline std::string getReadableName(const llvm::Value *V) {
        static std::unordered_map<const llvm::Value *, std::string> CachedNames;
        static std::unordered_map<const llvm::Function *, std::unordered_map<std::string, int>> LoadCounters;

        // If we've already generated a name for this Value, return it
        auto It = CachedNames.find(V);
        if (It != CachedNames.end()) {
            return It->second;
        }

        std::string Name;
        llvm::raw_string_ostream RSO(Name);

        if (const auto *Arg = llvm::dyn_cast<llvm::Argument>(V)) {
            RSO << Arg->getParent()->getName() << "_arg_" << Arg->getArgNo();

        } else if (const auto *Inst = llvm::dyn_cast<llvm::Instruction>(V)) {
            const auto *F = Inst->getFunction();
            std::string Opcode = Inst->getOpcodeName();

            if (Opcode == "load") {
            std::string base = F->getName().str() + "_load";
            if (Inst->getNumOperands() > 0 && Inst->getOperand(0)->hasName()) {
                base += "_" + Inst->getOperand(0)->getName().str();
            }

            int &Counter = LoadCounters[F][base];
            RSO << base << "_" << Counter++;
            } else {
            RSO << F->getName() << "_" << Opcode;
            if (V->hasName()) {
                RSO << "_" << V->getName();
            }
            }

        } else if (const auto *GV = llvm::dyn_cast<llvm::GlobalVariable>(V)) {
            RSO << "global_" << GV->getName();
        } else {
            RSO << "anonval";
        }

        std::string FinalName = RSO.str();
        CachedNames[V] = FinalName;
        return FinalName;
    }


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

            // llvm::outs() << "Computing direct aliases for function: " << F->getName() << "\n";

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

            // Print collected pointers for debugging
            // llvm::outs() << "List of pointers collected for alias analysis:(" << Pointers.size() << " total):\n";
            // int idx = 0;
            // for (const auto *Ptr : Pointers) {
            //     llvm::outs() << "  [" << idx++ << "] " << getReadableName(Ptr) << "\n";
            // }

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