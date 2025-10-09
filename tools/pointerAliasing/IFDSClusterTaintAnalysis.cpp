#include "IFDSClusterTaintAnalysis.h"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Operator.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/DataLayout.h"

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
    return pos == std::string::npos ? dem : dem.substr(0, pos); 
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

    static const llvm::Value *cellRep(const llvm::Value *V,
                                      const psr::AliasClusterInfo &ACI,
                                      const IFDSClusterTaintAnalysis &A) {
      if (!V) return nullptr;

      // If we’re modeling a memory cell, get the pointer feeding it, then its base
      if (const auto *LI = llvm::dyn_cast<llvm::LoadInst>(V)) {
        return ACI.getRepresentative(A.baseObject(LI->getPointerOperand()));
      }
      if (const auto *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(V)) {
        return ACI.getRepresentative(A.baseObject(GEP->getPointerOperand()));
      }
      if (V->getType()->isPointerTy()) {
        return ACI.getRepresentative(A.baseObject(V));
      }
      return nullptr;
    }

    // “transfer and kill” like upstream, but cluster-aware
    template <typename DSet>
    static auto transferAndKillFlowRep(const llvm::Value *To,
                                      const llvm::Value *From,
                                      const psr::AliasClusterInfo &ACI)
        -> FF {
      const auto *ToR   = ACI.getRepresentative(To);
      const auto *FromR = ACI.getRepresentative(From);
      const bool KillFrom = !From->hasNUsesOrMore(2);

      return FlowFunctions<ClusterIFDSDomain, C>::lambdaFlow(
          [ToR, FromR, KillFrom](const llvm::Value *In) -> std::set<const llvm::Value*> {
            std::set<const llvm::Value*> Out;
            if (In == FromR) {
              Out.insert(ToR);
              if (!KillFrom) Out.insert(FromR);
              return Out;
            }
            if (KillFrom && In == ToR) {
              return Out; // drop To when we “moved” it
            }
            Out.insert(In);
            return Out;
          });
    }

    template <typename DSet>
    static auto transferAndKillTwoFlowsRep(const llvm::Value *To,
                                          const llvm::Value *From1,
                                          const llvm::Value *From2,
                                          const psr::AliasClusterInfo &ACI)
        -> FF {
      const auto *ToR = ACI.getRepresentative(To);
      const auto *F1R = ACI.getRepresentative(From1);
      const auto *F2R = ACI.getRepresentative(From2);
      const bool KillF1 = !From1->hasNUsesOrMore(2);
      const bool KillF2 = !From2->hasNUsesOrMore(2);

      return FlowFunctions<ClusterIFDSDomain, C>::lambdaFlow(
          [ToR, F1R, F2R, KillF1, KillF2](const llvm::Value *In) -> std::set<const llvm::Value*> {
            std::set<const llvm::Value*> Out;
            const bool Hit = (In == F1R) || (In == F2R);
            if (Hit) Out.insert(ToR);
            if (!(KillF1 && In == F1R) && !(KillF2 && In == F2R) && In != ToR) {
              Out.insert(In);
            }
            return Out;
          });
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

  const llvm::DataLayout &IFDSClusterTaintAnalysis::DL() const {
    return IRDB_.getModule()->getDataLayout();
  }

  const llvm::Value *IFDSClusterTaintAnalysis::baseObject(const llvm::Value *V) const {
    if (!V) return nullptr;

    // Fast path: drop in-bounds constant offsets (handles many GEPs cleanly)
    V = V->stripInBoundsOffsets();

    // Ask LLVM for underlying objects (allocas/globals/args), bounded search
    llvm::SmallVector<llvm::Value*, 4> Under;
    llvm::getUnderlyingObject(const_cast<llvm::Value*>(V), 20);

    if (Under.size() == 1) return Under.front();

    // Conservative fallback: peel one level if obviously a pointer transform
    if (const auto *G = llvm::dyn_cast<llvm::GEPOperator>(V)) return G->getPointerOperand();
    if (const auto *B = llvm::dyn_cast<llvm::BitCastOperator>(V)) return B->getOperand(0);

    // Could not canonicalize further; keep as-is
    return V;
  }

  const llvm::Value *IFDSClusterTaintAnalysis::repBase(const llvm::Value *V) const {
    if (!V || isZeroValue(V)) return V;
    return ACI_.getRepresentative(baseObject(V));
  }

  // ---------- memory transfer rules (cluster-aware) ----------
  std::set<IFDSClusterTaintAnalysis::d_t>
  IFDSClusterTaintAnalysis::memTransfer(const Instruction* I, d_t In) const {
    std::set<d_t> Out;
    if (isZeroValue(In)) return Out;

    if (auto *SI = dyn_cast<StoreInst>(I)) {
      const Value *Val = SI->getValueOperand();
      const Value *Ptr = SI->getPointerOperand();
      const Value *ValR = repBase(Val);
      const Value *PtrR = repBase(Ptr);

      if (ValR == In) {
        Out.insert(PtrR);                 // content taint flows into pointee base
      }
      if (PtrR == In) {
        Out.insert(PtrR);                 // keep tainted cell tainted
      }
    } else if (auto *LI = dyn_cast<LoadInst>(I)) {
      const Value *PtrR = repBase(LI->getPointerOperand());
      if (PtrR == In) {
        Out.insert(repBase(LI));          // pointee base -> loaded SSA fact
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
    // store: value -> memory cell; keep tainted cell tainted
    if (const auto *Store = llvm::dyn_cast<llvm::StoreInst>(Curr)) {
      const Value *Ptr = Store->getPointerOperand();
      const Value *Val = Store->getValueOperand();
      const Value *PtrR = repBase(Ptr);
      const Value *ValR = repBase(Val);

      return FlowFunctions<ClusterIFDSDomain, C>::lambdaFlow(
        [this, PtrR, ValR](d_t In) -> std::set<d_t> {
          std::set<d_t> Out;
          if (this->isZeroValue(In)) { Out.insert(In); return Out; }

          if (In == ValR) {
            Out.insert(PtrR);                   // write taint into memory cell
            TaintedReps_.insert(PtrR);
          }
          if (In == PtrR) {
            Out.insert(PtrR);                   // keep cell tainted
          }
          Out.insert(In);
          return Out;
        });
    }

    // load: memory cell -> loaded SSA
    if (const auto *Load = llvm::dyn_cast<llvm::LoadInst>(Curr)) {
      return transferAndKillFlowRep<std::set<d_t>>(repBase(Load), repBase(Load->getPointerOperand()), ACI_);
    }

    // gep: address computation from tainted base
    if (const auto *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(Curr)) {
      return transferAndKillFlowRep<std::set<d_t>>(repBase(GEP), repBase(GEP->getPointerOperand()), ACI_);
    }

    // extractvalue / insertvalue (aggregate)
    if (const auto *EV = llvm::dyn_cast<llvm::ExtractValueInst>(Curr)) {
      return transferAndKillFlowRep<std::set<d_t>>(EV, EV->getAggregateOperand(), ACI_);
    }
    if (const auto *IV = llvm::dyn_cast<llvm::InsertValueInst>(Curr)) {
      return transferAndKillTwoFlowsRep<std::set<d_t>>(IV, IV->getAggregateOperand(),
                                                      IV->getInsertedValueOperand(), ACI_);
    }

    // cast: simple value copy
    if (const auto *Cast = llvm::dyn_cast<llvm::CastInst>(Curr)) {
      const auto *DstR = repBase(Cast);
      const auto *SrcR = repBase(Cast->getOperand(0));
      return FlowFunctions<ClusterIFDSDomain, C>::lambdaFlow(
        [DstR, SrcR](d_t In) -> std::set<d_t> {
          std::set<d_t> Out{In};
          if (In == SrcR) Out.insert(DstR);
          return Out;
        });
    }

    // identity
    return FlowFunctions<ClusterIFDSDomain, C>::identityFlow();
  }

  // ---------- call flow (actuals -> formals) + ZERO->sources ----------
  FF IFDSClusterTaintAnalysis::getCallFlowFunction(n_t CallSite, f_t DestFun) {
    const auto *CS = llvm::cast<llvm::CallBase>(CallSite);
    if (!DestFun) return FlowFunctions<ClusterIFDSDomain, C>::identityFlow();

    if (isSourceCall(CS, DestFun) || isSinkCall(CS, DestFun)) {
      // mirror upstream: kill all; seeding happens in summary/ret flows
      return FlowFunctions<ClusterIFDSDomain, C>::killAllFlows();
    }

    // actual -> formal (cluster-aware)
    return FlowFunctions<ClusterIFDSDomain, C>::lambdaFlow(
      [this, CS, DestFun](d_t In) -> std::set<d_t> {
        if (this->isZeroValue(In)) return {In};
        std::set<d_t> Out{repBase(In)};
        if (!DestFun->isDeclaration()) {
          unsigned I = 0;
          for (const auto &Formal : DestFun->args()) {
            if (I < CS->arg_size() && repBase(CS->getArgOperand(I)) == repBase(In)) {
              Out.insert(repBase(&Formal));
            }
            ++I;
          }
        }
        return Out;
      });
  }

  // ---------- return flow (formals/ret -> actuals/call) with fact-sensitive sanitizer ----------
  FF IFDSClusterTaintAnalysis::getRetFlowFunction(n_t CallSite, f_t Callee,
                                                  n_t ExitSite, n_t /*RetSite*/) {
    const auto *CS  = llvm::cast<llvm::CallBase>(CallSite);
    const auto *Ret = llvm::dyn_cast<llvm::ReturnInst>(ExitSite);

    return FlowFunctions<ClusterIFDSDomain, C>::lambdaFlow(
      [this, CS, Callee, Ret](d_t In) -> std::set<d_t> {
        std::set<d_t> Out;
        if (this->isZeroValue(In)) { Out.insert(In); return Out; }

        const auto *Rin = repBase(In);
        // formal -> actual (only pointer-typed formals, like upstream)
        unsigned I = 0;
        for (const auto &Formal : Callee->args()) {
          if (Formal.getType()->isPointerTy() && Rin == repBase(&Formal) && I < CS->arg_size()) {
            Out.insert(repBase(CS->getArgOperand(I)));
          }
          ++I;
        }
        // ret -> call result
        if (Ret && Ret->getReturnValue() && CS->getType() && !CS->getType()->isVoidTy()) {
          if (Rin == repBase(Ret->getReturnValue())) {
            Out.insert(repBase(CS));
          }
        }
        // keep original fact
        Out.insert(Rin);
        return Out;
      });
  }

  FF IFDSClusterTaintAnalysis::getCallToRetFlowFunction(n_t CallSite, n_t /*RetSite*/,
                                                        llvm::ArrayRef<f_t> Callees) {
    //const auto *CS = llvm::cast<llvm::CallBase>(CallSite);
    const bool HasDeclOnly = llvm::any_of(Callees, [](const Function *F){ return F->isDeclaration(); });

    return FlowFunctions<ClusterIFDSDomain, C>::lambdaFlow(
      [this, HasDeclOnly](d_t In) -> std::set<d_t> {
        if (this->isZeroValue(In)) return {In};
        const auto *Rin = repBase(In);

        // like upstream: keep non-pointer facts, and if any callee is decl-only, keep everything
        if (HasDeclOnly || !Rin->getType()->isPointerTy()) {
          return {Rin};
        }

        // otherwise, drop pointer facts that don't “flow alongside” (we do the same as original)
        return {};
      });
  }

  FF IFDSClusterTaintAnalysis::getSummaryFlowFunction(n_t CallSite, f_t DestFun) {
    const auto *CS = llvm::cast<llvm::CallBase>(CallSite);
    if (!DestFun) return nullptr;

    std::set<const Value*> Gen, Leak, Kill;
    TC_.forAllGeneratedValuesAt(CS, DestFun, [&](const Value* V){ Gen.insert(V); });
    TC_.forAllLeakCandidatesAt(CS, DestFun, [&](const Value* V){ Leak.insert(V); });
    TC_.forAllSanitizedValuesAt(CS, DestFun, [&](const Value* V){ Kill.insert(V); });

    // sret: if not generated, kill it
    if (CS->hasStructRetAttr()) {
      const auto *SRet = CS->getArgOperand(0);
      if (!Gen.count(SRet)) Kill.insert(SRet);
    }

    auto repifyBase = [this](const std::set<const Value*> &S){
      std::set<const Value*> R; for (auto *V : S) R.insert(repBase(V)); return R;
    };
    auto GenR  = repifyBase(Gen);
    auto LeakR = repifyBase(Leak);
    auto KillR = repifyBase(Kill);

    // also compute “cell reps” using base-object of pointer operands
    std::set<const Value*> GenCellR, LeakCellR;
    for (auto *V : Gen)  { if (auto *CR = cellRep(V, ACI_, *this))  GenCellR.insert(CR); }
    for (auto *V : Leak) { if (auto *CR = cellRep(V, ACI_, *this)) LeakCellR.insert(CR); }

    if (GenR.empty() && LeakR.empty() && KillR.empty()) {
      return nullptr; // fall back to normal/ret flows (and lib summaries if you wire them)
    }

    // ZERO seeds
    GenR.insert(LLVMZeroValue::getInstance());
    if (!GenCellR.empty()) GenCellR.insert(LLVMZeroValue::getInstance());

    return FlowFunctions<ClusterIFDSDomain, C>::lambdaFlow(
      [this, CS, DestFun,
      GenR{std::move(GenR)}, GenCellR{std::move(GenCellR)},
      LeakR{std::move(LeakR)}, LeakCellR{std::move(LeakCellR)},
      KillR{std::move(KillR)}](d_t In) -> std::set<d_t> {

        // generate from ZERO
        if (LLVMZeroValue::isLLVMZeroValue(In)) {
          std::set<d_t> Seeds = GenR;
          Seeds.insert(GenCellR.begin(), GenCellR.end());
          return Seeds;
        }

        const auto *Rs = repBase(In);
        const auto *Cs = cellRep(In, ACI_, *this);

        // leak check: by value or by memory cell
        const bool LeakByVal  = LeakR.count(Rs);
        const bool LeakByCell = Cs && LeakCellR.count(Cs);
        if (LeakByVal || LeakByCell) {
          pushSink(this->SinkHits_, CS, DestFun->getName().str(), Rs);
        }

        // kill facts sanitized here (by rep)
        if (KillR.count(Rs)) {
          return {};
        }

        return {Rs};
      }
    );
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