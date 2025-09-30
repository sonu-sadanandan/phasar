#pragma once

#include <set>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

#include "llvm/IR/Instruction.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Instructions.h"

#include "phasar/DataFlow/IfdsIde/IFDSTabulationProblem.h"
#include "phasar/DataFlow/IfdsIde/FlowFunctions.h"
#include "phasar/Domain/BinaryDomain.h"
#include "phasar/DataFlow/IfdsIde/InitialSeeds.h"
#include "phasar/PhasarLLVM/Domain/LLVMAnalysisDomain.h"
#include "phasar/PhasarLLVM/DataFlow/IfdsIde/LLVMZeroValue.h"

#include "phasar/PhasarLLVM/DB/LLVMProjectIRDB.h"
#include "phasar/PhasarLLVM/Pointer/AliasClusterInfo.h"
#include "phasar/PhasarLLVM/TaintConfig/LLVMTaintConfig.h"

namespace psr {

// Domain: keep LLVM default (d_t is Value*)
struct ClusterIFDSDomain : public LLVMIFDSAnalysisDomainDefault {
  using d_t = const llvm::Value *;
};

// Convenience aliases
using D  = typename ClusterIFDSDomain::d_t;
using C  = std::set<D>;
using FF = FlowFunctionPtrType<D, C>;

// ------------------ Analysis declaration ----------------
class IFDSClusterTaintAnalysis : public IFDSTabulationProblem<ClusterIFDSDomain> {
public:
  using n_t = typename ClusterIFDSDomain::n_t;
  using d_t = typename ClusterIFDSDomain::d_t;
  using f_t = typename ClusterIFDSDomain::f_t;
  using v_t = typename ClusterIFDSDomain::v_t;

  IFDSClusterTaintAnalysis(LLVMProjectIRDB &IRDB,
                           std::vector<std::string> EntryPoints,
                           const LLVMBasedICFG &ICFG,
                           AliasClusterInfo &ACI,
                           const LLVMTaintConfig &TC);

  // Flow functions
  FF getNormalFlowFunction(n_t Curr, n_t Succ) override;
  FF getCallFlowFunction(n_t CallSite, f_t DestFun) override;
  FF getRetFlowFunction(n_t CallSite, f_t Callee, n_t ExitSite, n_t RetSite) override;
  FF getCallToRetFlowFunction(n_t CallSite, n_t RetSite, llvm::ArrayRef<f_t> Callees) override;
  FF getSummaryFlowFunction(n_t CallSite, f_t DestFun) override;

  // Seeds & pretty-printing
  psr::InitialSeeds<n_t, d_t, psr::BinaryDomain> initialSeeds() override;

  bool isZeroValue(d_t Fact) const noexcept override {
    return Fact == this->getZeroValue();
  }

  std::string DToString(d_t Fact) const;
  std::string NToString(n_t Inst) const;

  // Results
  struct SinkHit {
    const llvm::Instruction *Call = nullptr;
    std::string SinkName;               // we’ll use callee base name
    const llvm::Value *ClusterRep = nullptr;
  };
  const std::vector<SinkHit> &getSinkHits() const { return SinkHits_; }

private:
  // Canonicalize to cluster representative
  const llvm::Value *rep(const llvm::Value *V) const;

  // Helpers
  static const llvm::Function* getCalledTarget(const llvm::CallBase *CB);
  static std::string demangledBase(const llvm::Function *F);

  bool isSourceCall(const llvm::CallBase *CB, const llvm::Function *Callee) const;
  bool isSinkCall(const llvm::CallBase *CB, const llvm::Function *Callee) const;
  bool isSanitizerCall(const llvm::CallBase *CB, const llvm::Function *Callee) const;

  // Cluster-aware memory transfer
  std::set<d_t> memTransfer(const llvm::Instruction *I, d_t In) const;

  // Members
  LLVMProjectIRDB &IRDB_;
  std::vector<std::string> EntryPoints_;
  const LLVMBasedICFG &ICFG_;
  AliasClusterInfo &ACI_;
  const LLVMTaintConfig &TC_;
  std::vector<SinkHit> SinkHits_;

  // (Optional) lightweight state you already had; keep if you still want it
  std::unordered_set<const llvm::Value*> TaintedReps_;
};

} // namespace psr
