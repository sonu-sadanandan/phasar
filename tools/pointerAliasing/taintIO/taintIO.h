// tools/pointerAliasing/taintIO/taintIO.h
#pragma once

#include <string>
#include <vector>

#include "llvm/ADT/ArrayRef.h"
#include "phasar/PhasarLLVM/DB/LLVMProjectIRDB.h"
#include "phasar/PhasarLLVM/TaintConfig/LLVMTaintConfig.h"

namespace psr {

struct TaintStats {
  size_t sources = 0;
  size_t sinks = 0;
  size_t sanitizers = 0;
};

struct BuiltConfig {
  // Programmatic taint configuration built from JSON (or other source)
  psr::LLVMTaintConfig Config;
  TaintStats Stats;
};

// Build LLVMTaintConfig from a JSON file (dies with error msg on failure).
// Keeps your existing CLI behavior while moving to programmatic config.
BuiltConfig buildConfigFromJSONOrDie(const std::string &path,
                                     const psr::LLVMProjectIRDB &IRDB);

// Build the human-readable text report you print/write.
std::string buildTextReport(const std::string &inputModule,
                            llvm::ArrayRef<std::string> entryPoints,
                            const TaintStats &stats,
                            const class IFDSClusterTaintAnalysis &analysis);

} // namespace psr
