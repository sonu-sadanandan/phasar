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
    psr::LLVMTaintConfig Config;
    TaintStats Stats;
  };

  BuiltConfig buildConfigFromJSONOrDie(const std::string &path,
                                      const psr::LLVMProjectIRDB &IRDB);

  std::string buildTextReport(const std::string &inputModule,
                              llvm::ArrayRef<std::string> entryPoints,
                              const TaintStats &stats,
                              const class IFDSClusterTaintAnalysis &analysis);

} // namespace psr
