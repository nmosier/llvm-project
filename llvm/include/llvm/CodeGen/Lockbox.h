#ifndef LLVM_CODEGEN_LOCKBOX_H
#define LLVM_CODEGEN_LOCKBOX_H

#include "llvm/IR/PassManager.h"

namespace llvm {

class LockboxPass : public PassInfoMixin<LockboxPass> {
public:
  explicit LockboxPass() = default;
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM);
};

}


#endif
