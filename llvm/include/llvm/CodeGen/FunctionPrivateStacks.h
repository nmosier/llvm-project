#ifndef LLVM_CODEGEN_FUNCTIONPRIVATESTACKS_H
#define LLVM_CODEGEN_FUNCTIONPRIVATESTACKS_H

#include "llvm/IR/PassManager.h"
#include "llvm/Support/CommandLine.h"

namespace llvm {

extern cl::opt<bool> EnableFunctionPrivateStacks;

class FunctionPrivateStacksPass : public PassInfoMixin<FunctionPrivateStacksPass> {
public:
  explicit FunctionPrivateStacksPass() = default;
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM); // NHM-TODO: Implement.
};

static inline constexpr uint64_t PrivateStackSize = 1024 * 1024;

}

#endif
