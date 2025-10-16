#include "taintIO.h"

#include <array>
#include <fstream>
#include <sstream>
#include <unordered_map>

#include "nlohmann/json.hpp"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"

#include "phasar/PhasarLLVM/Utils/LLVMShorthands.h"   
#include "phasar/PhasarLLVM/Pointer/AliasCommon.h"
#include "../IFDSClusterTaintAnalysis.h"              

using json = nlohmann::json;
using namespace llvm;

static std::string v2s(const llvm::Value *V) {
  std::string s;
  llvm::raw_string_ostream os(s);
  if (V) V->print(os); else os << "<null>";
  os.flush();
  return s;
}

namespace {

  struct FnRule {
    std::string Name;
    std::vector<unsigned> Args;
    bool TaintReturn = false;     // for sources
    bool SanitizeReturn = false;  // for sanitizers
  };

  struct RawRules {
    std::vector<FnRule> Sources;
    std::vector<FnRule> Sinks;
    std::vector<FnRule> Sanitizers;
  };

  static RawRules parseJSONToRulesOrDie(const std::string &path) {
    if (path.empty()) {
      errs() << "[error] --config is required for ifds-taint\n";
      ::exit(2);
    }
    std::ifstream in(path);
    if (!in) {
      errs() << "[error] cannot open config: " << path << "\n";
      ::exit(2);
    }

    json j; in >> j;
    RawRules R;

    auto parseList = [](const json &arr, bool isSource, RawRules &R) {
      for (const auto &e : arr) {
        FnRule f;
        if (e.contains("name")) f.Name = e.at("name").get<std::string>();
        else if (e.contains("func")) f.Name = e.at("func").get<std::string>();

        if (e.contains("tainted_args"))
          f.Args = e.at("tainted_args").get<std::vector<unsigned>>();
        else if (e.contains("args"))
          f.Args = e.at("args").get<std::vector<unsigned>>();

        if (isSource) {
          if (e.contains("taint_return"))
            f.TaintReturn = e.at("taint_return").get<bool>();
          else if (e.contains("returns_tainted"))
            f.TaintReturn = e.at("returns_tainted").get<bool>();
          else if (e.contains("return"))
            f.TaintReturn = e.at("return").get<bool>();
        }

        if (!f.Name.empty()) {
          (isSource ? R.Sources : R.Sinks).push_back(std::move(f));
        }
      }
    };

    // Old schemas
    if (j.contains("sources")) parseList(j["sources"], true, R);
    if (j.contains("sinks"))   parseList(j["sinks"],   false, R);
    if (j.contains("source_functions")) parseList(j["source_functions"], true, R);
    if (j.contains("sink_functions"))   parseList(j["sink_functions"],   false, R);

    // Newer schema with "functions"
    if (j.contains("functions") && j["functions"].is_array()) {
      for (const auto &fn : j["functions"]) {
        if (!fn.contains("name") || !fn.contains("params")) continue;
        FnRule f;
        f.Name = fn["name"].get<std::string>();
        const auto &params = fn["params"];

        if (params.contains("source")) {
          f.Args = params["source"].get<std::vector<unsigned>>();
          f.TaintReturn =
              params.contains("taint_return") ? params["taint_return"].get<bool>() : false;
          R.Sources.push_back(f);
        }
        if (params.contains("sink")) {
          FnRule g;
          g.Name = f.Name;
          g.Args = params["sink"].get<std::vector<unsigned>>();
          R.Sinks.push_back(g);
        }
      }
    }

    // Sanitizers (multiple spellings)
    if (j.contains("sanitizer_functions") && j["sanitizer_functions"].is_array()) {
      for (const auto &e : j["sanitizer_functions"]) {
        FnRule f;
        if (e.contains("name")) f.Name = e.at("name").get<std::string>();
        else if (e.contains("func")) f.Name = e.at("func").get<std::string>();

        if (e.contains("tainted_args"))
          f.Args = e.at("tainted_args").get<std::vector<unsigned>>();
        else if (e.contains("sanitize_args"))
          f.Args = e.at("sanitize_args").get<std::vector<unsigned>>();

        if (e.contains("sanitizes_return"))
          f.SanitizeReturn = e.at("sanitizes_return").get<bool>();

        if (!f.Name.empty()) R.Sanitizers.push_back(std::move(f));
      }
    }

    return R;
  }

  static const llvm::Function* getCalledTarget(const llvm::CallBase* CB) {
    if (!CB) return nullptr;
    if (const llvm::Function *F = CB->getCalledFunction()) return F;
    const llvm::Value *Callee = CB->getCalledOperand()->stripPointerCasts();
    return llvm::dyn_cast<llvm::Function>(Callee);
  }

  static inline std::array<std::string,3>
  calleeNames(const llvm::Function* F) {
    const std::string mangled = F->getName().str();
    std::string demFull = phasar::getReadableName(F); // "sink(char const*)"
    std::string demBase = demFull;
    if (auto pos = demBase.find('('); pos != std::string::npos) demBase.resize(pos);
    return {mangled, demFull, demBase};
  }

  } // namespace

  namespace psr {

  BuiltConfig buildConfigFromJSONOrDie(const std::string &path,
                                      const LLVMProjectIRDB & /*IRDB*/) {
    RawRules R = parseJSONToRulesOrDie(path);

    // name -> rule maps
    std::unordered_map<std::string, FnRule> SrcByName, SinkByName, SanByName;
    for (const auto &f : R.Sources)    SrcByName.emplace(f.Name, f);
    for (const auto &f : R.Sinks)      SinkByName.emplace(f.Name, f);
    for (const auto &f : R.Sanitizers) SanByName.emplace(f.Name, f);

    // Source callback
    LLVMTaintConfig::TaintDescriptionCallBackTy SrcCB =
      [SrcByName](const llvm::Instruction *I) -> std::set<const llvm::Value*> {
        std::set<const llvm::Value*> out;
        auto *CB = llvm::dyn_cast<llvm::CallBase>(I);
        if (!CB) return out;
        const llvm::Function *Callee = getCalledTarget(CB);
        if (!Callee) return out;

        const auto names = calleeNames(Callee);
        const FnRule* rule = nullptr;
        for (const auto& n : names) {
          auto it = SrcByName.find(n);
          if (it != SrcByName.end()) { rule = &it->second; break; }
        }
        if (!rule) return out;

        for (unsigned ai : rule->Args)
          if (ai < CB->arg_size()) out.insert(CB->getArgOperand(ai));
        if (rule->TaintReturn && CB->getType() && !CB->getType()->isVoidTy())
          out.insert(I);
        return out;
      };

    // Sink callback (returns operands considered leak candidates)
    LLVMTaintConfig::TaintDescriptionCallBackTy SinkCB =
      [SinkByName](const llvm::Instruction *I) -> std::set<const llvm::Value*> {
        std::set<const llvm::Value*> out;
        auto *CB = llvm::dyn_cast<llvm::CallBase>(I);
        if (!CB) return out;
        const llvm::Function *Callee = getCalledTarget(CB);
        if (!Callee) return out;

        const auto names = calleeNames(Callee);
        const FnRule* rule = nullptr;
        for (const auto& n : names) {
          auto it = SinkByName.find(n);
          if (it != SinkByName.end()) { rule = &it->second; break; }
        }
        if (!rule) return out;

        for (unsigned ai : rule->Args)
          if (ai < CB->arg_size()) out.insert(CB->getArgOperand(ai));
        return out;
      };

    // Sanitizer callback (returns values that become sanitized)
    LLVMTaintConfig::TaintDescriptionCallBackTy SanCB =
      [SanByName](const llvm::Instruction *I) -> std::set<const llvm::Value*> {
        std::set<const llvm::Value*> out;
        auto *CB = llvm::dyn_cast<llvm::CallBase>(I);
        if (!CB) return out;
        const llvm::Function *Callee = getCalledTarget(CB);
        if (!Callee) return out;

        const auto names = calleeNames(Callee);
        const FnRule* rule = nullptr;
        for (const auto& n : names) {
          auto it = SanByName.find(n);
          if (it != SanByName.end()) { rule = &it->second; break; }
        }
        if (!rule) return out;

        for (unsigned ai : rule->Args)
          if (ai < CB->arg_size()) out.insert(CB->getArgOperand(ai));
        if (rule->SanitizeReturn && CB->getType() && !CB->getType()->isVoidTy())
          out.insert(I);
        return out;
      };

    BuiltConfig B{
      /*Config=*/psr::LLVMTaintConfig(std::move(SrcCB), std::move(SinkCB), std::move(SanCB)),
      /*Stats =*/ { R.Sources.size(), R.Sinks.size(), R.Sanitizers.size() }
    };
    return B;
  }

  std::string buildTextReport(const std::string &inputModule,
                              ArrayRef<std::string> entryPoints,
                              const TaintStats &stats,
                              const IFDSClusterTaintAnalysis &analysis) {
    std::string s; raw_string_ostream os(s);

    const auto &hits = analysis.getSinkHits();

    os << "=== IFDS Cluster Taint Report ===\n";
    os << "Input: " << inputModule << "\n";
    os << "Entry points: ";
    for (size_t i = 0; i < entryPoints.size(); ++i) {
      if (i) os << ", ";
      os << entryPoints[i];
    }
    os << "\nSources: " << stats.sources
      << "  Sanitizers: " << stats.sanitizers
      << "  Sinks: " << stats.sinks
      << "\nSink hits: " << hits.size() << "\n\n";

    for (const auto &h : hits) {
      os << "[SINK] " << h.SinkName << " @ " << v2s(h.Call)
        << "  (cluster rep: " << v2s(h.ClusterRep) << ")\n";
    }

    os.flush();
    return s;
  }

} // namespace psr
