#include "IFDSClusterTaintAnalysis.h"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Operator.h"

#include "phasar/DataFlow/IfdsIde/FlowFunctions.h"
#include "phasar/PhasarLLVM/DataFlow/IfdsIde/LLVMZeroValue.h"
#include "phasar/PhasarLLVM/TaintConfig/TaintConfigUtilities.h"
#include "phasar/PhasarLLVM/Utils/LLVMShorthands.h"
#include "phasar/PhasarLLVM/Pointer/AliasCommon.h"
#include "phasar/Utils/Logger.h"

#include <unordered_set>
#include <vector>

using namespace llvm;
using psr::AliasClusterInfo;

namespace psr {

// ---------- small utils (as members, matching your header) ----------
const Function* IFDSClusterTaintAnalysis::getCalledTarget(const CallBase* CB) {
  if (!CB) return nullptr;
  if (const Function *F = CB->getCalledFunction())
    return F;
  const Value *Callee = CB->getCalledOperand()->stripPointerCasts();
  return dyn_cast<Function>(Callee);
}

std::string IFDSClusterTaintAnalysis::demangledBase(const llvm::Function *F) {
  std::string dem = phasar::getReadableName(F); // e.g., "sink(char const*)"
  auto pos = dem.find('(');
  return pos == std::string::npos ? dem : dem.substr(0, pos); // -> "sink"
}

// Small local helper to de-dup sink hits
namespace {
  static void pushSink(std::vector<IFDSClusterTaintAnalysis::SinkHit> &Hits,
                      const llvm::Instruction *Call,
                      const std::string &Name,
                      const llvm::Value *Rep) {
    for (const auto &h : Hits) {
      if (h.Call == Call && h.ClusterRep == Rep && h.SinkName == Name) {
        return;
      }
    }
    Hits.push_back({Call, Name, Rep});
  }

  static const llvm::Value *loadBasePtr(const llvm::Value *V) {
    if (const auto *LI = llvm::dyn_cast<llvm::LoadInst>(V)) {
      return LI->getPointerOperand()->stripPointerCasts();
    }
    return nullptr;
  }

  static const llvm::Value *cellRep(const llvm::Value *V,
                                    const psr::AliasClusterInfo &ACI) {
    if (const auto *Base = loadBasePtr(V)) {
      return ACI.getRepresentative(Base); // cluster rep of the memory cell
    }
    return nullptr;
  }
} // namespace

// ---------- ctor ----------
IFDSClusterTaintAnalysis::IFDSClusterTaintAnalysis(
    LLVMProjectIRDB &IRDB,
    std::vector<std::string> EntryPoints,
    const LLVMBasedICFG &ICFG,
    AliasClusterInfo &ACI,
    const LLVMTaintConfig &TC)
  : IFDSTabulationProblem(&IRDB, EntryPoints, LLVMZeroValue::getInstance()),
    IRDB_(IRDB),
    EntryPoints_(std::move(EntryPoints)),
    ICFG_(ICFG),
    ACI_(ACI),
    TC_(TC) {}

// ---------- cluster rep ----------
const Value* IFDSClusterTaintAnalysis::rep(const Value* V) const {
  if (!V || isZeroValue(V)) return V;
  return ACI_.getRepresentative(V);
}

// ---------- tiny classification helpers ----------
static inline bool isAssignLike(const Instruction* I) {
  return isa<BitCastInst>(I) || isa<GetElementPtrInst>(I) ||
         isa<PHINode>(I)    || I->isCast()                ||
         isa<SelectInst>(I) || isa<UnaryInstruction>(I)   ||
         isa<BinaryOperator>(I);
}

// ---------- memory transfer rules (cluster-aware) ----------
std::set<IFDSClusterTaintAnalysis::d_t>
IFDSClusterTaintAnalysis::memTransfer(const Instruction* I, d_t In) const {
  std::set<d_t> Out;
  if (isZeroValue(In)) return Out;

  if (auto *SI = dyn_cast<StoreInst>(I)) {
    const Value *Val = SI->getValueOperand();
    const Value *Ptr = SI->getPointerOperand();
    if (rep(Val) == In) {
      Out.insert(rep(Ptr));          // value -> memory location
    }
    if (rep(Ptr) == In) {
      Out.insert(In);                // keep tainted location tainted
    }
  } else if (auto *LI = dyn_cast<LoadInst>(I)) {
    const Value *Ptr = LI->getPointerOperand();
    if (rep(Ptr) == In) {
      Out.insert(rep(LI));           // memory location -> loaded SSA
    }
  }
  return Out;
}

bool IFDSClusterTaintAnalysis::isSourceCall(const llvm::CallBase *CB,
                                            const llvm::Function *Callee) const {
  for (const auto &Arg : Callee->args()) {
    if (TC_.isSource(&Arg)) return true;
  }
  const auto &Callback = TC_.getRegisteredSourceCallBack();
  if (!Callback) return false;

  auto AdditionalFacts = Callback(CB);
  if (AdditionalFacts.empty()) return false;

  if (AdditionalFacts.count(CB)) return true;
  return std::any_of(CB->arg_begin(), CB->arg_end(),
                     [&AdditionalFacts](const auto &Arg) {
                       return AdditionalFacts.count(Arg.get());
                     });
}

bool IFDSClusterTaintAnalysis::isSinkCall(const llvm::CallBase *CB,
                                          const llvm::Function *Callee) const {
  for (const auto &Arg : Callee->args()) {
    if (TC_.isSink(&Arg)) return true;
  }
  const auto &Callback = TC_.getRegisteredSinkCallBack();
  if (!Callback) return false;

  auto AdditionalLeaks = Callback(CB);
  if (AdditionalLeaks.empty()) return false;

  if (AdditionalLeaks.count(CB)) return true;
  return std::any_of(CB->arg_begin(), CB->arg_end(),
                     [&AdditionalLeaks](const auto &Arg) {
                       return AdditionalLeaks.count(Arg.get());
                     });
}

bool IFDSClusterTaintAnalysis::isSanitizerCall(const llvm::CallBase* /*CB*/,
                                               const llvm::Function* Callee) const {
  return std::any_of(Callee->arg_begin(), Callee->arg_end(),
                     [this](const auto &Arg){ return TC_.isSanitizer(&Arg); });
}


// ---------- normal flow ----------
FF IFDSClusterTaintAnalysis::getNormalFlowFunction(n_t Curr, n_t /*Succ*/) {
  // Debug hook (optional)
  if (auto *CB = dyn_cast<CallBase>(Curr)) {
    if (const auto *F = getCalledTarget(CB)) {
      llvm::outs() << "[hook] " << __FUNCTION__
                   << " callee mangled=" << F->getName()
                   << " dem=" << phasar::getReadableName(F) << "\n";
    } else {
      llvm::outs() << "[hook] " << __FUNCTION__ << " indirect call\n";
    }
  }

  return FlowFunctions<ClusterIFDSDomain, C>::lambdaFlow(
    [this, Curr](d_t In) -> std::set<d_t> {
      std::set<d_t> Out;
      if (this->isZeroValue(In)) {
        Out.insert(In);
        return Out;
      }

      In = rep(In);

      // Assign-like copy
      if (isAssignLike(Curr)) {
        for (const llvm::Value *Op : Curr->operand_values()) {
          if (rep(Op) == In) {
            const auto *RC = rep(Curr);
            Out.insert(RC);
            TaintedReps_.insert(RC); // mark the derived SSA as tainted
            llvm::outs() << "[dbg] ASSIGN taint -> " << psr::llvmIRToShortString(rep(Curr)) << "\n";
            break;
          }
        }
        Out.insert(In);
        return Out;
      }

      // Memory traffic
      if (isa<StoreInst>(Curr) || isa<LoadInst>(Curr)) {
        auto MemOut = memTransfer(Curr, In);
        for (auto *V : MemOut) {
          llvm::outs() << "[dbg] MEM taint -> " << psr::llvmIRToShortString(V) << "\n";
          Out.insert(V);
          TaintedReps_.insert(V);    // mark tainted memory/loads
        }
        Out.insert(In);
        return Out;
      }

      // Identity
      Out.insert(In);
      return Out;
    });
}

// ---------- call flow (actuals -> formals) + ZERO->sources ----------
FF IFDSClusterTaintAnalysis::getCallFlowFunction(n_t CallSite, f_t DestFun) {
  auto *CB = llvm::dyn_cast<llvm::CallBase>(CallSite);

  // --- DEBUG (keep if you want) ---
  if (CB) {
    if (const auto *F = getCalledTarget(CB)) {
      llvm::outs() << "[hook] " << __FUNCTION__
                   << " callee mangled=" << F->getName()
                   << " dem=" << phasar::getReadableName(F) << "\n";
    } else {
      llvm::outs() << "[hook] " << __FUNCTION__ << " indirect call\n";
    }
  }

  if (!CB || !DestFun) {
    return FlowFunctions<ClusterIFDSDomain, C>::identityFlow();
  }

  //  Only kill on SOURCE calls. Let facts survive at SINK calls so the summary
  //  can see the incoming tainted arg and record the leak.
  if (isSourceCall(CB, DestFun)) {
    return FlowFunctions<ClusterIFDSDomain, C>::lambdaFlow(
      [this](d_t In){ return this->isZeroValue(In) ? std::set<d_t>{In} : std::set<d_t>{}; });
  }

  return FlowFunctions<ClusterIFDSDomain, C>::lambdaFlow(
    [this, CB, DestFun](d_t In) -> std::set<d_t> {
      if (this->isZeroValue(In)) return {In};
      if (!DestFun->isDeclaration()) {
        std::set<d_t> Out;
        d_t Rin = rep(In);
        unsigned ArgIdx = 0;
        for (const llvm::Argument &Formal : DestFun->args()) {
          if (ArgIdx < CB->arg_size() && rep(CB->getArgOperand(ArgIdx)) == Rin) {
            Out.insert(rep(&Formal));
          }
          ++ArgIdx;
        }
        Out.insert(Rin);
        return Out;
      }
      // For declarations (e.g., free), just keep the fact.
      return {rep(In)};
    });
}



// ---------- return flow (formals/ret -> actuals/call) with fact-sensitive sanitizer ----------
FF IFDSClusterTaintAnalysis::getRetFlowFunction(n_t CallSite, f_t Callee,
                                                n_t ExitSite, n_t /*RetSite*/) {
  if (auto *CBlog = dyn_cast<CallBase>(CallSite)) {
    if (const auto *F = getCalledTarget(CBlog)) {
      llvm::outs() << "[hook] " << __FUNCTION__
                   << " callee mangled=" << F->getName()
                   << " dem=" << phasar::getReadableName(F) << "\n";
    } else {
      llvm::outs() << "[hook] " << __FUNCTION__ << " indirect call\n";
    }
  }

  auto *CB  = dyn_cast<CallBase>(CallSite);
  auto *Ret = dyn_cast<ReturnInst>(ExitSite);

  return FlowFunctions<ClusterIFDSDomain, C>::lambdaFlow(
    [this, CB, Ret, Callee](d_t In) -> std::set<d_t> {
      std::set<d_t> Out;

      if (this->isZeroValue(In)) {
        Out.insert(In);
        return Out;
      }

      In = rep(In);

      if (!CB || !Callee) {
        Out.insert(In);
        return Out;
      }

      // Collect sanitized values at this call (cluster-aware)
      bool CallResultSanitized = false;
      std::unordered_set<const llvm::Value*> Sanitized;
      TC_.forAllSanitizedValuesAt(CB, Callee, [&](const llvm::Value* V) {
        Sanitized.insert(rep(V));
      });

      // Kill only THIS fact if it's sanitized here
      if (Sanitized.count(In)) {
        return Out; // drop just this one
      }

      // If the call's result is sanitized, don't propagate ret -> call result
      if (Sanitized.count(rep(CB))) {
        CallResultSanitized = true;
      }

      // formal -> actual
      unsigned ArgIdx = 0;
      for (const llvm::Argument &Formal : Callee->args()) {
        if (rep(&Formal) == In && ArgIdx < CB->arg_size()) {
          const auto *RA = rep(CB->getArgOperand(ArgIdx));
          Out.insert(RA);
          TaintedReps_.insert(RA); // mark actual as tainted
          llvm::outs() << "[dbg] ARG taint -> " << psr::llvmIRToShortString(RA) << "\n";
        }
        ++ArgIdx;
      }

      // ret value -> call result (unless the call result is sanitized)
      if (!CallResultSanitized &&
          Ret && Ret->getReturnValue() &&
          CB->getType() && !CB->getType()->isVoidTy()) {
        if (rep(Ret->getReturnValue()) == In) {
          const auto *CR = rep(CB);
          Out.insert(CR);
          TaintedReps_.insert(CR);
          llvm::outs() << "[dbg] RET taint -> " << psr::llvmIRToShortString(CR) << "\n";
        }
      }

      return Out;
    });
}

FF IFDSClusterTaintAnalysis::getCallToRetFlowFunction(n_t CallSite, n_t /*RetSite*/,
                                                      llvm::ArrayRef<f_t> Callees) {
  auto *CB = dyn_cast<CallBase>(CallSite);
  if (!CB) {
    return FlowFunctions<ClusterIFDSDomain, C>::identityFlow();
  }

  return FlowFunctions<ClusterIFDSDomain, C>::lambdaFlow(
    [this](d_t In) -> std::set<d_t> {
      if (this->isZeroValue(In)) return {In};
      return {rep(In)};
    });
}

FF IFDSClusterTaintAnalysis::getSummaryFlowFunction(n_t CallSite, f_t DestFun) {
  auto *CS = llvm::cast<llvm::CallBase>(CallSite);
  if (!DestFun) return nullptr;

  // Buckets from TaintConfigUtilities (clusterize them!)
  std::set<const llvm::Value*> Gen;
  std::set<const llvm::Value*> Leak;
  std::set<const llvm::Value*> Kill;

  // Fill from config (exactly like IFDSTaintAnalysis)
  TC_.forAllGeneratedValuesAt(CS, DestFun, [&](const llvm::Value* V){ Gen.insert(V); });
  TC_.forAllLeakCandidatesAt(CS, DestFun, [&](const llvm::Value* V){ Leak.insert(V); });
  TC_.forAllSanitizedValuesAt(CS, DestFun, [&](const llvm::Value* V){ Kill.insert(V); });

  // sret handling (same rationale as PhASAR)
  if (CS->hasStructRetAttr()) {
    const auto *SRet = CS->getArgOperand(0);
    if (!Gen.count(SRet)) {
      Kill.insert(SRet);
    }
  }

  // Map every collected value to its cluster representative
  auto repify = [this](const std::set<const llvm::Value*> &InSet) {
    std::set<const llvm::Value*> Out;
    for (auto *V : InSet) Out.insert(rep(V));
    return Out;
  };
  auto GenR  = repify(Gen);
  auto LeakR = repify(Leak);
  auto KillR = repify(Kill);
  std::set<const llvm::Value*> LeakCellR;
  for (const auto *V : Leak) {
    if (const auto *CR = cellRep(V, ACI_)) {
      LeakCellR.insert(CR);
    }
  }

  // If nothing to do, return nullptr (lets solver use your normal/ret flows)
  if (GenR.empty() && LeakR.empty() && KillR.empty()) return nullptr;

  // Add ZERO to Gen like PhASAR
  GenR.insert(LLVMZeroValue::getInstance());

  const Function *F = getCalledTarget(CS);
  const std::string SinkName = F ? demangledBase(F) : std::string("<indirect>");

  if (const llvm::Function *Enclosing = CS->getFunction()) {
    unsigned argIdx = 0;
    for (const llvm::Argument &Formal : Enclosing->args()) {
      if (argIdx < CS->arg_size()) {
        const llvm::Value *Act = CS->getArgOperand(argIdx);
        const auto *ActR = rep(Act);
        const auto *FormR = rep(&Formal);
        if (GenR.count(ActR)) {
          GenR.insert(FormR); // ensure formal is tainted too
        }
      }
      ++argIdx;
    }
  }

  return FlowFunctions<ClusterIFDSDomain, C>::lambdaFlow(
    [this, CS, SinkName,
    GenR{std::move(GenR)}, LeakR{std::move(LeakR)},
    KillR{std::move(KillR)}, LeakCellR{std::move(LeakCellR)}]
    (d_t Source) -> std::set<d_t> {

      if (LLVMZeroValue::isLLVMZeroValue(Source)) {
        return GenR; // generate sources
      }

      const auto *Rs = rep(Source);               // value rep
      const auto *Cs = cellRep(Source, ACI_);     // cell rep (may be null)

      // -- DEBUG: keep this while testing --
      llvm::outs() << "[sum] call=" << psr::llvmIRToShortString(CS)
                  << " Rs=" << psr::llvmIRToShortString(Rs)
                  << " Cs=" << (Cs ? psr::llvmIRToShortString(Cs) : "null")
                  << " Gen=" << GenR.size()
                  << " LeakV=" << LeakR.size()
                  << " LeakC=" << LeakCellR.size()
                  << " Kill=" << KillR.size() << "\n";

      // 1) same value rep or 2) same memory-cell rep
      const bool isLeakByValue = LeakR.count(Rs);
      const bool isLeakByCell  = Cs && LeakCellR.count(Cs);

      if (isLeakByValue || isLeakByCell) {
        // Optional extra debug dump:
        llvm::outs() << "[sum] LEAK hit at "
                    << psr::llvmIRToShortString(CS)
                    << " via " << (isLeakByValue ? "value" : "cell")
                    << " Rs=" << psr::llvmIRToShortString(Rs)
                    << (Cs ? " Cs=" + psr::llvmIRToShortString(Cs) : "")
                    << "\n";
        // record
        pushSink(this->SinkHits_, CS, SinkName, Rs);
        // do not kill; we just report
      }

      if (KillR.count(Rs)) {
        return {}; // drop just this fact
      }

      return {Rs};
    });
}


// ---------- seeds ----------
psr::InitialSeeds<IFDSClusterTaintAnalysis::n_t,
                  IFDSClusterTaintAnalysis::d_t,
                  psr::BinaryDomain>
IFDSClusterTaintAnalysis::initialSeeds() {
  psr::InitialSeeds<n_t, d_t, psr::BinaryDomain> Seeds;
  for (const auto &Name : EntryPoints_) {
    if (auto *F = IRDB_.getModule()->getFunction(Name)) {
      if (!F->isDeclaration()) {
        n_t Start = &*(F->getEntryBlock().begin());
        Seeds.addSeed(Start, this->getZeroValue());
      }
    }
  }
  return Seeds;
}

std::string IFDSClusterTaintAnalysis::DToString(d_t Fact) const {
  if (this->isZeroValue(Fact)) return "ZERO";
  return llvmIRToShortString(Fact);
}
std::string IFDSClusterTaintAnalysis::NToString(n_t Inst) const {
  return llvmIRToShortString(Inst);
}

} // namespace psr




/*
FF IFDSClusterTaintAnalysis::getSummaryFlowFunction(n_t CallSite, f_t) {
  auto *CB = llvm::dyn_cast<llvm::CallBase>(CallSite);
  if (!CB) return nullptr;

  unsigned SrcIdx = 0, SinkIdx = 0;
  bool IsSrc  = isSourceCall(CB, SrcIdx);
  bool IsSink = isSinkCall(CB, SinkIdx);
  if (!IsSrc && !IsSink) return nullptr;

  return FlowFunctions<ClusterIFDSDomain, C>::lambdaFlow(
    [this, CB, IsSrc, SrcIdx, IsSink, SinkIdx](d_t In) -> std::set<d_t> {
      std::set<d_t> Out;

      if (this->isZeroValue(In)) {
        if (IsSrc) {
          const auto &S = Spec_.Sources[SrcIdx];
          auto Gen = genFromSource(CB, S);
          for (auto *F : Gen) Out.insert(rep(F));

          // --- NEW: propagate "freed" across call boundary if arg is a formal
          if (!S.Args.empty()) {
            unsigned pos = S.Args.front();
            if (pos < CB->arg_size()) {
              const llvm::Value *Arg = CB->getArgOperand(pos);
              const llvm::Value *ArgRep = rep(Arg);
              FreedReps_.insert(ArgRep); // always

              if (auto *Formal = llvm::dyn_cast<llvm::Argument>(Arg)) {
                unsigned aidx = Formal->getArgNo();
                const llvm::Function *F = Formal->getParent();
                llvm::outs() << "[summary] callee: mangled=" << F->getName()
                            << " dem=" << phasar::getReadableName(F)
                            << " base=" << demangledBase(F) << "\n";

                // Walk direct call sites to F and mark their actuals as freed
                for (const llvm::Use &U : F->uses()) {
                  if (auto *CI = llvm::dyn_cast<llvm::CallBase>(U.getUser())) {
                    if (aidx < CI->arg_size()) {
                      const llvm::Value *Actual = CI->getArgOperand(aidx);
                      FreedReps_.insert(rep(Actual));
                    }
                  }
                }
              }
            }
          }
        }
        Out.insert(In);
        return Out;
      }

      In = rep(In);

      if (IsSink) {
        const auto &S = Spec_.Sinks[SinkIdx];
        for (unsigned pos : S.Args) {
          if (pos < CB->arg_size() && rep(CB->getArgOperand(pos)) == In) {
            SinkHits_.push_back({CB, S.Name, In});
            break;
          }
        }
        // Stateful safety net: even if IFDS fact didn't line up, check caller actuals
        if (!S.Args.empty()) {
          unsigned pos = S.Args.front();
          if (pos < CB->arg_size()) {
            const llvm::Value *ArgRep = rep(CB->getArgOperand(pos));
            if (FreedReps_.count(ArgRep)) {
              SinkHits_.push_back({CB, S.Name, ArgRep});
            }
          }
        }
      }

      Out.insert(In);
      return Out;
    });
}*/