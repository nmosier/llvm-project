#include "llvm/CodeGen/MPK.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/IntrinsicsX86.h"
#include "llvm/Pass.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/InitializePasses.h"

using namespace llvm;

namespace {

void run(Function &F) {
  BasicBlock &B = F.getEntryBlock();
  IRBuilder<> IRB(&B, B.getFirstNonPHIOrDbgOrAlloca());
#if 0
  IRB.CreateIntrinsic(IRB.getVoidTy(), Intrinsic::x86_wrpkru, {IRB.getInt32(0)});
#elif 0
  AllocaInst *Alloca = IRB.CreateAlloca(IRB.getInt32Ty());
  Instruction *Val = IRB.CreateIntrinsic(IRB.getInt32Ty(), Intrinsic::x86_rdpkru, {});
  IRB.CreateStore(Val, Alloca, /*isVolatile*/true);
#endif
}

}


PreservedAnalyses MPKPass::run(Function &F, FunctionAnalysisManager &FAM) {
  ::run(F);
  return PreservedAnalyses::none();
}


namespace {

class MPKLegacyPass final : public FunctionPass {
public:
  static char ID;

  MPKLegacyPass() : FunctionPass(ID) {
    initializeMPKLegacyPassPass(*PassRegistry::getPassRegistry());
  }

  bool runOnFunction(Function &F) override {
    ::run(F);
    return true;
  }
};

}

char MPKLegacyPass::ID = 0;
INITIALIZE_PASS(MPKLegacyPass, "mpk", "MPK Pass", false, false)

FunctionPass *llvm::createMPKPass() { return new MPKLegacyPass(); }
