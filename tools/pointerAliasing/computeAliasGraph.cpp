#include "phasar/PhasarLLVM/Pointer/LLVMAliasSet.h"
#include "phasar/Config/phasar-config.h"

void LLVMAliasSet::computeDirectAliases(llvm::Function *F) {
    if (!F || F->isDeclaration()) {
      return;
    }
  
    // Check if we already analyzed the function
    if (auto [Unused, Inserted] = AnalyzedFunctions.insert(F); !Inserted) {
      return;
    }
  
    PHASAR_LOG_LEVEL_CAT(DEBUG, "LLVMAliasSet",
                         "Computing direct aliases for function: " << F->getName());
  
    llvm::AAResults &AA = *PTA.getAAResults(F);
    const llvm::DataLayout &DL = F->getParent()->getDataLayout();
    
  
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
  
    // Check aliasing between all pairs of pointers
    // Ensure the loop is within a valid function or block
    for (size_t i = 0; i < Pointers.size(); ++i) {
      for (size_t j = i + 1; j < Pointers.size(); ++j) {
        const llvm::Value *A = Pointers[i];
        const llvm::Value *B = Pointers[j];
  
        llvm::AliasResult Result = AA.alias(A, B);
        if (Result != llvm::AliasResult::NoAlias) {
          AliasKind Kind = (Result == llvm::AliasResult::MustAlias) ? AliasKind::MustAlias : AliasKind::MayAlias;
          addAlias(A, B, Kind);
          llvm::errs() << *A;

        }
      }
    }
  }
  