#ifndef LLVM_CODEGEN_FUNCTIONPRIVATESTACKS_H
#define LLVM_CODEGEN_FUNCTIONPRIVATESTACKS_H

#include <llvm/IR/PassManager.h>

namespace llvm {

class FunctionPrivateStacksPass : public PassInfoMixin<FunctionPrivateStacksPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

}

#endif
