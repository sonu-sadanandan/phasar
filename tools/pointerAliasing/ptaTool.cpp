#include "IFDSClusterTaintAnalysis.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"

#include "phasar/PhasarLLVM/DB/LLVMProjectIRDB.h"
#include "phasar/PhasarLLVM/ControlFlow/LLVMBasedICFG.h"
#include "phasar/PhasarLLVM/Pointer/AliasClusterInfo.h"
#include "phasar/PhasarLLVM/Pointer/AliasPipeline.h"
#include "phasar/DataFlow/IfdsIde/Solver/IFDSSolver.h"
#include "phasar/PhasarLLVM/TaintConfig/LLVMTaintConfig.h"
#include "phasar/PhasarLLVM/Pointer/AliasCommon.h"
#include "phasar/PhasarLLVM/Utils/LLVMShorthands.h"


#include "taintIO/taintIO.h"
#include "phasar/Utils/IO.h"

#include <sstream>
#include <unordered_map>

using namespace llvm;

namespace {
cl::OptionCategory CAT("Cluster IFDS Taint Options");

cl::list<std::string> InputModules(cl::Positional, cl::desc("<input IR file>"),
                                   cl::OneOrMore, cl::cat(CAT));

cl::opt<std::string> AnalysisKind("analysis",
  cl::desc("Analysis to run: 'clusters' or 'ifds-taint'"),
  cl::value_desc("name"),
  cl::init("clusters"),
  cl::cat(CAT));

cl::opt<std::string> ConfigPath("config",
  cl::desc("Path to JSON taint config (sources/sinks) [ifds-taint only]"),
  cl::value_desc("file"),
  cl::init(""),
  cl::cat(CAT));

cl::opt<std::string> EntryPointsOpt("entry-points",
  cl::desc("Comma-separated entry points (default: main)"),
  cl::value_desc("ep1,ep2,..."),
  cl::init("main"),
  cl::cat(CAT));

cl::opt<std::string> EmitTextReport("emit-text-report",
  cl::desc("Write a taint text report to this file (stdout if omitted)"),
  cl::value_desc("file"),
  cl::init(""),
  cl::cat(CAT));

cl::opt<bool> ShowClusterMembers("show-cluster-members",
  cl::desc("Print cluster members to stdout (clusters mode)"),
  cl::init(false),
  cl::cat(CAT));

cl::opt<std::string> EmitClustersReport("emit-clusters-report",
  cl::desc("Write full clusters (with members) to this file"),
  cl::value_desc("file"),
  cl::init(""),
  cl::cat(CAT));

cl::opt<unsigned> MaxMembersToPrint("max-cluster-members",
  cl::desc("Limit printed members per cluster (0 = no limit)"),
  cl::init(0),
  cl::cat(CAT));

static std::vector<std::string> splitCSV(const std::string &s) {
  std::vector<std::string> out;
  std::string cur;
  std::istringstream is(s);
  while (std::getline(is, cur, ',')) {
    if (!cur.empty()) out.push_back(cur);
  }
  return out;
}

// Build a textual cluster report. If includeMembers=false, only header+counts.
static std::string buildClustersText(const psr::AliasClusterInfo &ACI,
                                     size_t totalPointers,
                                     bool includeMembers,
                                     unsigned maxMembersToPrint) {
  const auto &p2r = ACI.getPointerToRepMap();

  // Bucket pointers by representative
  std::unordered_map<const llvm::Value*, std::vector<const llvm::Value*>> buckets;
  buckets.reserve(p2r.size());
  for (const auto &kv : p2r) {
    buckets[kv.second].push_back(kv.first);
  }

  std::string s;
  raw_string_ostream os(s);

  os << "=== Alias Clusters ===\n";
  os << "Total pointers: " << totalPointers
     << "  |  Clusters: " << buckets.size() << "\n";

  if (!includeMembers) {
    os.flush();
    return s;
  }

  os << "\n";
  unsigned idx = 0;
  for (const auto &kv : buckets) {
    const llvm::Value *rep = kv.first;
    const auto &members = kv.second;

    os << "C" << idx++
       << "  rep=" << psr::llvmIRToShortString(rep)
       << "  size=" << members.size() << "\n";

    unsigned printed = 0;
    for (const auto *p : members) {
      if (maxMembersToPrint && printed >= maxMembersToPrint) {
        os << "  ... (" << (members.size() - printed) << " more not shown)\n";
        break;
      }
      os << "  - " << psr::llvmIRToShortString(p) << "\n";
      ++printed;
    }
    os << "\n";
  }

  os.flush();
  return s;
}

// Identify direct callee (strip bitcasts)
static const llvm::Function* getCalledTarget(const llvm::CallBase* CB) {
  if (!CB) return nullptr;
  if (const llvm::Function *F = CB->getCalledFunction()) return F;
  const llvm::Value *Callee = CB->getCalledOperand()->stripPointerCasts();
  return llvm::dyn_cast<llvm::Function>(Callee);
}

static inline std::array<std::string,3> namesOf(const llvm::Function* F) {
  const std::string mangled = F->getName().str();
  std::string demFull = phasar::getReadableName(F);
  std::string demBase = demFull;
  if (auto pos = demBase.find('('); pos != std::string::npos) demBase.resize(pos);
  return {mangled, demFull, demBase};
}

static inline bool isAnyOf(const std::array<std::string,3>& got,
                           std::initializer_list<const char*> want) {
  for (auto &g : got) for (auto w : want) if (g == w) return true;
  return false;
}

static psr::LLVMTaintConfig makeSimpleCallbackConfig() {
  using CB = psr::LLVMTaintConfig::TaintDescriptionCallBackTy;

  //SOURCE: taint the call result of source()
  CB src = [](const llvm::Instruction* I) -> std::set<const llvm::Value*> {
    std::set<const llvm::Value*> out;
    auto *call = llvm::dyn_cast<llvm::CallBase>(I);
    if (!call) return out;
    if (const auto *F = getCalledTarget(call)) {
      auto n = namesOf(F);
      if (isAnyOf(n, {"free", "free()", "free", "_ZdlPv", "operator delete(void*)", "operator delete", "_Z6sourcev"})) {
        if (call->arg_size() > 0) out.insert(call->getArgOperand(0));
      }
    }
    return out;
  };
  // CB src = [](const llvm::Instruction* I) {
  //   std::set<const llvm::Value*> out;
  //   auto *call = llvm::dyn_cast<llvm::CallBase>(I);
  //   if (!call) return out;
  //   if (const auto *F = getCalledTarget(call)) {
  //     if (F->getName() == "free" && call->arg_size() > 0) {
  //       out.insert(call->getArgOperand(0));
  //     }
  //   }
  //   return out;
  // };

  // SINK: arg(0) of sink(...) is a leak candidate
  CB sink = [](const llvm::Instruction* I) -> std::set<const llvm::Value*> {
    std::set<const llvm::Value*> out;
    auto *call = llvm::dyn_cast<llvm::CallBase>(I);
    if (!call) return out;
    if (const auto *F = getCalledTarget(call)) {
      auto n = namesOf(F);
      if (isAnyOf(n, {"free", "free()", "free", "_ZdlPv", "operator delete(void*)", "operator delete", "_Z4sinkPKc"})) {
        if (call->arg_size() > 0) {
          out.insert(call->getArgOperand(0));
          llvm::outs() << "[tc] SINK   match at " << n[0] << " / " << n[1] << " arg0\n";
        }
      }
    }
    return out;
  };

  // SANITIZER: sanitize(...) returns a clean value
  CB san = [](const llvm::Instruction* I) -> std::set<const llvm::Value*> {
    std::set<const llvm::Value*> out;
    auto *call = llvm::dyn_cast<llvm::CallBase>(I);
    if (!call) return out;
    if (const auto *F = getCalledTarget(call)) {
      auto n = namesOf(F);
      if (isAnyOf(n, {"_Z8sanitizePKc", "sanitize(char const*)", "sanitize"})) {
        if (I->getType() && !I->getType()->isVoidTy()) {
          out.insert(I);
          llvm::outs() << "[tc] SAN    match at " << n[0] << " / " << n[1] << " (return)\n";
        }
      }
    }
    return out;
  };

  return psr::LLVMTaintConfig(std::move(src), std::move(sink), std::move(san));
}

} // namespace

int main(int argc, const char **argv) {
  cl::HideUnrelatedOptions({&CAT});
  cl::ParseCommandLineOptions(argc, argv,
      "Cluster-representative IFDS Taint (PhASAR)\n");

  if (InputModules.size() != 1) {
    errs() << "[error] this PhASAR build expects exactly one IR file; got "
           << InputModules.size() << "\n";
    return 2;
  }

  // IRDB (single module)
  psr::LLVMProjectIRDB IRDB(InputModules[0]);

  // Entry points
  auto EntryPoints = splitCSV(EntryPointsOpt);
  if (EntryPoints.empty()) EntryPoints = {"main"};

  // Alias clusters
  auto Pipe = psr::buildAliasClusters(IRDB, psr::AliasAnalysisType::CFLAnders);
  psr::AliasClusterInfo &ACI = *Pipe.Clusters;

  // -------- Mode switch --------
  if (AnalysisKind == "clusters") {
    const bool includeMembersToStdout = ShowClusterMembers;

    const std::string stdoutText =
        buildClustersText(ACI, Pipe.TotalPointers,
                          /*includeMembers=*/includeMembersToStdout,
                          /*maxMembersToPrint=*/MaxMembersToPrint);

    outs() << stdoutText;

    if (!EmitClustersReport.empty()) {
      const std::string fileText =
          buildClustersText(ACI, Pipe.TotalPointers,
                            /*includeMembers=*/true,
                            /*maxMembersToPrint=*/MaxMembersToPrint);
      std::error_code EC;
      raw_fd_ostream Out(EmitClustersReport, EC, sys::fs::OF_Text);
      if (EC) {
        errs() << "[error] cannot write clusters report: " << EmitClustersReport
               << " (" << EC.message() << ")\n";
        return 3;
      }
      Out << fileText;
    }
    return 0;
  }

  if (AnalysisKind == "ifds-taint") {
    // ICFG (on-the-fly)
    psr::LLVMBasedICFG ICFG(&IRDB, psr::CallGraphAnalysisType::OTF, EntryPoints);

    psr::LLVMTaintConfig TC(
      psr::LLVMTaintConfig::TaintDescriptionCallBackTy{},
      psr::LLVMTaintConfig::TaintDescriptionCallBackTy{},
      psr::LLVMTaintConfig::TaintDescriptionCallBackTy{}
    );
    psr::TaintStats Stats{};

    if (!ConfigPath.empty()) {
      auto Built = psr::buildConfigFromJSONOrDie(ConfigPath, IRDB);
      TC = std::move(Built.Config);
      Stats = Built.Stats;
    } else {
      TC = makeSimpleCallbackConfig();
    }

    auto &src = TC.getRegisteredSourceCallBack();
    auto &snk = TC.getRegisteredSinkCallBack();
    auto &san = TC.getRegisteredSanitizerCallBack();
    llvm::outs() << "[dbg] callbacks set: "
                << "src=" << (src ? "Y" : "N")
                << " sink=" << (snk ? "Y" : "N")
                << " san=" << (san ? "Y" : "N")
                << "\n";

    // Analysis + solver
    psr::IFDSClusterTaintAnalysis Analysis(IRDB, EntryPoints, ICFG, ACI, TC);
    psr::IFDSSolver<psr::ClusterIFDSDomain> Solver(Analysis, &ICFG);
    Solver.solve();

    llvm::outs() << "[dbg] solver done; hits="
             << Analysis.getSinkHits().size() << "\n";
    for (const auto &h : Analysis.getSinkHits()) {
      llvm::outs() << "  [hit] " << h.SinkName
                  << "  call=" << psr::llvmIRToShortString(h.Call)
                  << "  rep="  << psr::llvmIRToShortString(h.ClusterRep)
                  << "\n";
    }
    // Report
    const std::string Report =
        psr::buildTextReport(InputModules[0], EntryPoints, Stats, Analysis);

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
    return 0;
  }

  errs() << "[error] unknown --analysis=" << AnalysisKind
         << " (use 'clusters' or 'ifds-taint')\n";
  return 2;
}
