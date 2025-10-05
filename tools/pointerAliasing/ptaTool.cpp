#include "IFDSClusterTaintAnalysis.h"
#include "Metrics.h" 

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"

#include "phasar/DataFlow/IfdsIde/Solver/IFDSSolver.h"
#include "phasar/PhasarLLVM/ControlFlow/LLVMBasedICFG.h"
#include "phasar/PhasarLLVM/DB/LLVMProjectIRDB.h"
#include "phasar/PhasarLLVM/Pointer/AliasClusterInfo.h"
#include "phasar/PhasarLLVM/Pointer/AliasPipeline.h"
#include "phasar/PhasarLLVM/TaintConfig/LLVMTaintConfig.h"
#include "phasar/PhasarLLVM/Utils/LLVMShorthands.h"

#include "taintIO/taintIO.h"
#include "phasar/Utils/IO.h"

#include <sstream>
#include <unordered_map>
#include <vector>
#include <memory>

using namespace llvm;

namespace {

cl::OptionCategory CAT("Cluster IFDS Taint Options");

cl::list<std::string> InputModules(
    cl::Positional, cl::desc("<input IR file>"), cl::OneOrMore, cl::cat(CAT));

cl::opt<std::string> AnalysisKind(
    "analysis",
    cl::desc("Analysis to run: 'clusters' or 'ifds-taint'"),
    cl::value_desc("name"),
    cl::init("clusters"),
    cl::cat(CAT));

cl::opt<std::string> ConfigPath(
    "config",
    cl::desc("Path to JSON taint config (sources/sinks) [ifds-taint only]"),
    cl::value_desc("file"),
    cl::init(""),
    cl::cat(CAT));

cl::opt<std::string> EntryPointsOpt(
    "entry-points",
    cl::desc("Comma-separated entry points (default: main)"),
    cl::value_desc("ep1,ep2,..."),
    cl::init("main"),
    cl::cat(CAT));

cl::opt<std::string> EmitTextReport(
    "emit-text-report",
    cl::desc("Write a taint text report to this file (stdout if omitted)"),
    cl::value_desc("file"),
    cl::init(""),
    cl::cat(CAT));

cl::opt<bool> ShowClusterMembers(
    "show-cluster-members",
    cl::desc("Print cluster members to stdout (clusters mode)"),
    cl::init(false),
    cl::cat(CAT));

cl::opt<std::string> EmitClustersReport(
    "emit-clusters-report",
    cl::desc("Write full clusters (with members) to this file"),
    cl::value_desc("file"),
    cl::init(""),
    cl::cat(CAT));

cl::opt<unsigned> MaxMembersToPrint(
    "max-cluster-members",
    cl::desc("Limit printed members per cluster (0 = no limit)"),
    cl::init(0),
    cl::cat(CAT));

// ---------------- small helpers ----------------
static std::vector<std::string> splitCSV(const std::string &S) {
  std::vector<std::string> Out;
  std::string Cur;
  std::istringstream Is(S);
  while (std::getline(Is, Cur, ',')) {
    if (!Cur.empty()) Out.push_back(Cur);
  }
  return Out;
}

static const llvm::Function *getCalledTarget(const llvm::CallBase *CB) {
  if (!CB) return nullptr;
  if (const llvm::Function *F = CB->getCalledFunction()) return F;
  const llvm::Value *Callee = CB->getCalledOperand()->stripPointerCasts();
  return llvm::dyn_cast<llvm::Function>(Callee);
}

static inline std::array<std::string,3> namesOf(const llvm::Function *F) {
  const std::string mangled = F->getName().str();
  std::string demFull = phasar::getReadableName(F);
  std::string demBase = demFull;
  if (auto pos = demBase.find('('); pos != std::string::npos) demBase.resize(pos);
  return {mangled, demFull, demBase};
}

static inline bool isAnyOf(const std::array<std::string,3> &got,
                           std::initializer_list<const char*> want) {
  for (const auto &g : got) for (const auto w : want) if (g == w) return true;
  return false;
}

// ------------- cluster report builder -------------
static std::string buildClustersText(const psr::AliasClusterInfo &ACI,
                                     size_t TotalPointers,
                                     bool IncludeMembers,
                                     unsigned MaxMembers) {
  const auto &P2R = ACI.getPointerToRepMap();

  std::unordered_map<const llvm::Value*, std::vector<const llvm::Value*>> Buckets;
  Buckets.reserve(P2R.size());
  for (const auto &KV : P2R) {
    Buckets[KV.second].push_back(KV.first);
  }

  std::string S;
  raw_string_ostream OS(S);

  OS << "=== Alias Clusters ===\n";
  OS << "Total pointers: " << TotalPointers
     << "  |  Clusters: " << Buckets.size() << "\n";

  if (!IncludeMembers) { OS.flush(); return S; }

  OS << "\n";
  unsigned Idx = 0;
  for (const auto &KV : Buckets) {
    const llvm::Value *Rep = KV.first;
    const auto &Members = KV.second;

    OS << "C" << Idx++
       << "  rep="  << psr::llvmIRToShortString(Rep)
       << "  size=" << Members.size() << "\n";

    unsigned printed = 0;
    for (const auto *P : Members) {
      if (MaxMembers && printed >= MaxMembers) {
        OS << "  ... (" << (Members.size() - printed) << " more not shown)\n";
        break;
      }
      OS << "  - " << psr::llvmIRToShortString(P) << "\n";
      ++printed;
    }
    OS << "\n";
  }

  OS.flush();
  return S;
}

// ------------- default callback config (unchanged) -------------
static psr::LLVMTaintConfig makeSimpleCallbackConfig() {
  using CB = psr::LLVMTaintConfig::TaintDescriptionCallBackTy;

  CB src = [](const llvm::Instruction *I) {
    std::set<const llvm::Value*> Out;
    auto *Call = llvm::dyn_cast<llvm::CallBase>(I);
    if (!Call) return Out;
    if (const auto *F = getCalledTarget(Call)) {
      if (F->getName() == "free" && Call->arg_size() > 0) {
        Out.insert(Call->getArgOperand(0));
        llvm::outs() << "[tc] SOURCE   match at "
                       << " arg0\n";
      }
    }
    return Out;
  };

  CB sink = [](const llvm::Instruction *I) {
    std::set<const llvm::Value*> Out;
    auto *Call = llvm::dyn_cast<llvm::CallBase>(I);
    if (!Call) return Out;
    if (const auto *F = getCalledTarget(Call)) {
      auto N = namesOf(F);
      if (isAnyOf(N, {"free","free()","_ZdlPv","operator delete(void*)",
                      "operator delete","_Z4sinkPKc"})) {
        if (Call->arg_size() > 0) {
          Out.insert(Call->getArgOperand(0));
          llvm::outs() << "[tc] SINK   match at " << N[0] << " / " << N[1]
                       << " arg0\n";
        }
      }
    }
    return Out;
  };

  CB san = [](const llvm::Instruction *I) {
    std::set<const llvm::Value*> Out;
    auto *Call = llvm::dyn_cast<llvm::CallBase>(I);
    if (!Call) return Out;
    if (const auto *F = getCalledTarget(Call)) {
      auto N = namesOf(F);
      if (isAnyOf(N, {"_Z8sanitizePKc","sanitize(char const*)","sanitize"})) {
        if (I->getType() && !I->getType()->isVoidTy()) {
          Out.insert(I);
          llvm::outs() << "[tc] SAN    match at " << N[0] << " / " << N[1]
                       << " (return)\n";
        }
      }
    }
    return Out;
  };

  return psr::LLVMTaintConfig(std::move(src), std::move(sink), std::move(san));
}

} // namespace

// ========================= MAIN =========================
int main(int argc, const char **argv) {
  psr::perf::ScopedPhase total{"TOTAL"};

  cl::HideUnrelatedOptions({&CAT});
  cl::ParseCommandLineOptions(argc, argv,
      "Cluster-representative IFDS Taint (PhASAR)\n");

  if (InputModules.size() != 1) {
    errs() << "[error] this PhASAR build expects exactly one IR file; got "
           << InputModules.size() << "\n";
    return 2;
  }

  // IRDB
  std::unique_ptr<psr::LLVMProjectIRDB> IRDBPtr;
  {
    psr::perf::ScopedPhase p{"IRDB load"};
    IRDBPtr = std::make_unique<psr::LLVMProjectIRDB>(InputModules[0]);
  }
  auto &IRDB = *IRDBPtr;

  // Entry points
  auto EntryPoints = splitCSV(EntryPointsOpt);
  if (EntryPoints.empty()) EntryPoints = {"main"};

  // Alias clusters
  std::optional<psr::AliasPipelineResult> Pipe;
  {
    psr::perf::ScopedPhase p{"Alias cluster build"};
    Pipe = psr::buildAliasClusters(IRDB, psr::AliasAnalysisType::CFLAnders);
  }
  psr::AliasClusterInfo &ACI = *Pipe->Clusters;

  // -------- clusters mode --------
  if (AnalysisKind == "clusters") {
    {
      psr::perf::ScopedPhase p{"Cluster reporting"};
      const std::string stdoutText =
          buildClustersText(ACI, Pipe->TotalPointers,
                            /*IncludeMembers=*/ShowClusterMembers,
                            /*MaxMembers=*/MaxMembersToPrint);
      outs() << stdoutText;

      if (!EmitClustersReport.empty()) {
        const std::string fileText =
            buildClustersText(ACI, Pipe->TotalPointers,
                              /*IncludeMembers=*/true,
                              /*MaxMembers=*/MaxMembersToPrint);
        std::error_code EC;
        raw_fd_ostream Out(EmitClustersReport, EC, sys::fs::OF_Text);
        if (EC) {
          errs() << "[error] cannot write clusters report: "
                 << EmitClustersReport << " (" << EC.message() << ")\n";
          return 3;
        }
        Out << fileText;
      }
    }
    psr::perf::printPhaseSummary();
    return 0;
  }

  // -------- ifds-taint mode --------
  if (AnalysisKind == "ifds-taint") {
    // ICFG
    std::unique_ptr<psr::LLVMBasedICFG> ICFGPtr;
    {
      psr::perf::ScopedPhase p{"ICFG build (OTF)"};
      ICFGPtr = std::make_unique<psr::LLVMBasedICFG>(
          &IRDB, psr::CallGraphAnalysisType::OTF, EntryPoints);
    }
    auto &ICFG = *ICFGPtr;

    // Taint config
    psr::LLVMTaintConfig TC(
      psr::LLVMTaintConfig::TaintDescriptionCallBackTy{},
      psr::LLVMTaintConfig::TaintDescriptionCallBackTy{},
      psr::LLVMTaintConfig::TaintDescriptionCallBackTy{}
    );
    psr::TaintStats Stats{};
    {
      psr::perf::ScopedPhase p{"Taint config load"};
      if (!ConfigPath.empty()) {
        auto Built = psr::buildConfigFromJSONOrDie(ConfigPath, IRDB);
        TC = std::move(Built.Config);
        Stats = Built.Stats;
      } else {
        TC = makeSimpleCallbackConfig();
      }
    }

    {
      auto &src = TC.getRegisteredSourceCallBack();
      auto &snk = TC.getRegisteredSinkCallBack();
      auto &san = TC.getRegisteredSanitizerCallBack();
      llvm::outs() << "[dbg] callbacks set: "
                   << "src="  << (src ? "Y" : "N")
                   << " sink="<< (snk ? "Y" : "N")
                   << " san=" << (san ? "Y" : "N") << "\n";
    }

    // Analysis + solver
    std::unique_ptr<psr::IFDSClusterTaintAnalysis> Analysis;
    std::unique_ptr<psr::IFDSSolver<psr::ClusterIFDSDomain>> Solver;
    {
      psr::perf::ScopedPhase p{"IFDS construction"};
      Analysis = std::make_unique<psr::IFDSClusterTaintAnalysis>(
          IRDB, EntryPoints, ICFG, ACI, TC);
      Solver = std::make_unique<psr::IFDSSolver<psr::ClusterIFDSDomain>>(
          *Analysis, &ICFG);
    }
    {
      psr::perf::ScopedPhase p{"IFDS solve (taint)"};
      Solver->solve();
    }

    llvm::outs() << "[dbg] solver done; hits="
                 << Analysis->getSinkHits().size() << "\n";
    for (const auto &H : Analysis->getSinkHits()) {
      llvm::outs() << "  [hit] " << H.SinkName
                   << "  call=" << psr::llvmIRToShortString(H.Call)
                   << "  rep="  << psr::llvmIRToShortString(H.ClusterRep)
                   << "\n";
    }

    {
      psr::perf::ScopedPhase p{"Report build/output"};
      const std::string Report =
          psr::buildTextReport(InputModules[0], EntryPoints, Stats, *Analysis);

      if (EmitTextReport.empty()) {
        outs() << Report;
      } else {
        std::error_code EC;
        raw_fd_ostream Out(EmitTextReport, EC, sys::fs::OF_Text);
        if (EC) {
          errs() << "[error] cannot write report: " << EmitTextReport
                 << " (" << EC.message() << ")\n";
          return 3;
        }
        Out << Report;
      }
    }

    psr::perf::printPhaseSummary();
    return 0;
  }

  errs() << "[error] unknown --analysis=" << AnalysisKind
         << " (use 'clusters' or 'ifds-taint')\n";
  return 2;
}
