#ifndef PHASAR_ALIAS_COMMON_H
#define PHASAR_ALIAS_COMMON_H

#include <string>
#include <unordered_map>
#include "llvm/IR/Value.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/GlobalVariable.h"

enum class AliasKind { MustAlias, MayAlias };

namespace phasar {

inline std::string getReadableName(const llvm::Value *V) {
  static std::unordered_map<const llvm::Value *, std::string> CachedNames;
  static std::unordered_map<const llvm::Function *, std::unordered_map<std::string, int>> LoadCounters;

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

} // namespace phasar

#endif
