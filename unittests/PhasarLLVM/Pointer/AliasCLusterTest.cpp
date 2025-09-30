#include "phasar/PhasarLLVM/Pointer/AliasGraph.h"
#include "phasar/PhasarLLVM/Pointer/DirectAliasComputer.h"
#include "phasar/PhasarLLVM/DB/LLVMProjectIRDB.h"
#include "phasar/PhasarLLVM/Pointer/AliasAnalysisView.h"
#include "phasar/PhasarLLVM/Utils/LLVMShorthands.h"
#include "phasar/PhasarLLVM/Passes/ValueAnnotationPass.h"
#include "phasar/Config/Configuration.h"
#include "TestConfig.h"

#include "gtest/gtest.h"
#include "llvm/ADT/StringExtras.h"

using namespace psr;
using namespace phasar;
using namespace llvm;

std::vector<std::unordered_set<std::string>> getAliasClusters(const std::string &IRFilePath) {
    ValueAnnotationPass::resetValueID();
    LLVMProjectIRDB IRDB(IRFilePath);
    if (!IRDB.isValid()) {
        throw std::runtime_error("Invalid IRDB for file: " + IRFilePath);
    }

    AliasGraph Graph;
    std::unordered_set<const llvm::Function *> Analyzed;
    auto AAObj = AliasAnalysisView::create(IRDB, true, AliasAnalysisType::CFLAnders);

    for (auto &F : *IRDB.getModule()) {
        if (F.isDeclaration())
        continue;

        DirectAliasComputer DAC(
        AAObj->getAAResults(&F),
        Analyzed,
        [&](const llvm::Value *A, const llvm::Value *B, AliasKind Kind) {
            Graph.addAlias(A, B, Kind);
        },
        [&](const llvm::Value *P) {
            Graph.ensureExists(P);
        });

        DAC.computeDirectAliases(&F);
    }

    auto Clusters = Graph.computeAliasClusters();

    std::vector<std::unordered_set<std::string>> NamedClusters;
    for (const auto &Cluster : Clusters) {
        std::unordered_set<std::string> Named;
        for (const auto *V : Cluster) {
        Named.insert(getReadableName(V));
        }
        NamedClusters.push_back(Named);
    }
    return NamedClusters;
}

void validateAliasClusters(const std::string &IRFilePath, const std::vector<std::unordered_set<std::string>> &ExpectedClusters) {

    ValueAnnotationPass::resetValueID();
    LLVMProjectIRDB IRDB(IRFilePath);
    ASSERT_TRUE(IRDB.isValid());

    auto ActualClusters = getAliasClusters(IRFilePath);
    ASSERT_EQ(ActualClusters.size(), ExpectedClusters.size()) << "Cluster count mismatch";

    for (const auto &Expected : ExpectedClusters) {
        bool found = false;
        for (const auto &Actual : ActualClusters) {
        if (Expected == Actual) {
            found = true;
            break;
        }
        }
        ASSERT_TRUE(found) << "Expected cluster not found: { "
                        << llvm::join(Expected.begin(), Expected.end(), ", ") << " }";
    }
    llvm::outs() << "\nTest Passed for basic_alias_test.ll with " << ActualClusters.size()
               << " clusters.\n";
}

TEST(DirectAliasClustering, BasicClusteringTest01) {
  ValueAnnotationPass::resetValueID();
  LLVMProjectIRDB IRDB(unittest::PathToLLTestFiles + "pointers/basic_01_cpp.ll");
  ASSERT_TRUE(IRDB.isValid());

  AliasGraph Graph;
  std::unordered_set<const llvm::Function *> Analyzed;
  auto AAObj = AliasAnalysisView::create(IRDB, true, AliasAnalysisType::CFLAnders);

  for (auto &F : *IRDB.getModule()) {
    if (F.isDeclaration())
      continue;

    DirectAliasComputer DAC(
      AAObj->getAAResults(&F),
      Analyzed,
      [&](const llvm::Value *A, const llvm::Value *B, AliasKind Kind) {
        Graph.addAlias(A, B, Kind);
      },
      [&](const llvm::Value *P) {
        Graph.ensureExists(P);
      });

    DAC.computeDirectAliases(&F);
  }

  auto Clusters = Graph.computeAliasClusters();

  std::vector<std::unordered_set<std::string>> ExpectedClusters = {
      { "main_alloca_p" },
      { "main_load_p_0" },
      { "main_alloca_i" },
  };

  std::vector<std::unordered_set<std::string>> ActualNamed;
  for (const auto &Cluster : Clusters) {
    std::unordered_set<std::string> Named;
    for (const auto *V : Cluster) {
      Named.insert(getReadableName(V));
    }
    ActualNamed.push_back(Named);
  }

  ASSERT_EQ(ActualNamed.size(), ExpectedClusters.size()) << "Cluster count mismatch";

    llvm::outs() << "Expected Clusters:\n";
    for (const auto &Expected : ExpectedClusters) {
    llvm::outs() << "{ ";
    for (const auto &Val : Expected) {
        llvm::outs() << Val << ", ";
    }
    llvm::outs() << "}\n";
    }

    llvm::outs() << "\nActual Clusters:\n";
    for (const auto &Actual : ActualNamed) {
    llvm::outs() << "{ ";
    for (const auto &Val : Actual) {
        llvm::outs() << Val << ", ";
    }
    llvm::outs() << "}\n";
    }

  for (const auto &Expected : ExpectedClusters) {
    bool found = false;
    for (const auto &Actual : ActualNamed) {
      if (Expected == Actual) {
        found = true;
        break;
      }
    }
    ASSERT_TRUE(found) << "Expected cluster not found: { "
                       << llvm::join(Expected.begin(), Expected.end(), ", ") << " }";
  }

  llvm::outs() << "\nTest Passed for basic_alias_test.ll with " << Clusters.size()
               << " clusters.\n";
}

TEST(DirectAliasClustering, BasicClusteringTest02) {
  validateAliasClusters((unittest::PathToLLTestFiles + "pointers/basic_01_cpp.ll").str(),
    {
      { "main_alloca_p" },
      { "main_load_p_0" },
      { "main_alloca_i" },
    }
  );
}

TEST(DirectAliasClustering, BasicClusteringTest03) {
  validateAliasClusters((unittest::PathToLLTestFiles + "pointers/aliasing_test_case_cpp.ll").str(),
    {
        { "main_alloca_p3" },
        { "main_alloca_p2" },
        { "main_alloca_p1" },
        { "main_alloca_retval" },
        { "main_alloca_y" },
        { "main_load_p1_2" },
        { "_Z6modifyPiS__load_b.addr_0" },
        { "_Z10pass_aliasPi_alloca_p.addr" },
        { "_Z6modifyPiS__load_a.addr_0" },
        { "_Z6modifyPiS__arg_0" },
        { "_Z10pass_aliasPi_arg_0" },
        { "main_load_p1_0" },
        { "main_load_p3_0" },
        { "_Z6modifyPiS__arg_1" },
        { "_Z6modifyPiS__alloca_a.addr" },
        { "main_load_p1_1" },
        { "_Z6modifyPiS__alloca_b.addr" },
        { "_Z10pass_aliasPi_load_p.addr_0" },
        { "_Z10pass_aliasPi_load_p.addr_1" },
        { "main_load_p2_0" },
        { "main_alloca_x" }
    }
  );
}

TEST(DirectAliasClustering, BasicClusteringTest04) {
  validateAliasClusters((unittest::PathToLLTestFiles + "pointers/aliasing_test_case_02_cpp.ll").str(),
    {
      { "global_gp" },
      { "main_alloca_v2" },
      { "main_alloca_v1" },
      { "main_alloca_retval" },
      { "_Z10use_structP1S_load_a_0" },
      { "_Z10use_structP1S_load_s.addr_1", "_Z10use_structP1S_getelementptr_a" },
      { "_Z10use_structP1S_load_b_0" },
      { "_Z10set_structP1SPiS1__alloca_y.addr" },
      { "_Z10use_structP1S_alloca_s.addr" },
      { "_Z10set_structP1SPiS1__getelementptr_a", "_Z10set_structP1SPiS1__load_s.addr_0" },
      { "main_alloca_obj" },
      { "_Z10set_structP1SPiS1__load_y.addr_0" },
      { "global_g2" },
      { "_Z10use_structP1S_getelementptr_b" },
      { "_Z10set_structP1SPiS1__load_s.addr_1" },
      { "_Z10set_structP1SPiS1__getelementptr_b" },
      { "_Z10set_structP1SPiS1__load_x.addr_0" },
      { "_Z10set_structP1SPiS1__arg_0" },
      { "_Z10set_structP1SPiS1__arg_1" },
      { "_Z10use_structP1S_load_s.addr_0" },
      { "_Z10set_structP1SPiS1__arg_2" },
      { "_Z10set_structP1SPiS1__alloca_x.addr" },
      { "_Z10use_structP1S_arg_0" },
      { "_Z10set_structP1SPiS1__alloca_s.addr" }
    }
  );
}


int main(int Argc, char **Argv) {
  ::testing::InitGoogleTest(&Argc, Argv);
  return RUN_ALL_TESTS();
}
