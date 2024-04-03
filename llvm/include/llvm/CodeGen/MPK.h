#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {

class MPKPass : public PassInfoMixin<MPKPass> {
public:
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM);
};

}



