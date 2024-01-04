#include "llvm/CodeGen/FunctionPrivateStacks.h" // NHM-TODO: Maybe don't need this?

#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/InitializePasses.h"
#include "llvm/CodeGen/Passes.h"

using namespace llvm;

namespace llvm {

// NHM-FIXME: Fixup flags.
cl::opt<bool> EnableFunctionPrivateStacks(
    "x86-fps", cl::init(false), cl::Hidden);
}

namespace {

class FunctionPrivateStacks {
  Module &M;
  LLVMContext &Ctx;
  bool Changed;

  void runOnFunction(Function &F);
  
public:
  FunctionPrivateStacks(Module &M) : M(M), Ctx(M.getContext()), Changed(false) {}
  bool run();
};

void FunctionPrivateStacks::runOnFunction(Function &F) {
  // NHM-FIXME: Assert only works on 64-bit architectures.
  
  // Create stack pointer and frame pointer global variables.
  auto *PtrTy = PointerType::getUnqual(Ctx);
  auto CreateGV = [&] (StringRef Stem) -> GlobalVariable * {
    return new GlobalVariable(M, PtrTy, /*isConstant*/false, GlobalVariable::PrivateLinkage, Constant::getNullValue(PtrTy), "__fps_" + Stem + "_" + F.getName(), nullptr, GlobalVariable::GeneralDynamicTLSModel);
  };

  GlobalVariable *StackPtr = CreateGV("stackptr");
}

bool FunctionPrivateStacks::run() {
  for (Function &F : M)
    if (!F.isDeclaration())
      runOnFunction(F);
  return Changed;
}

class FunctionPrivateStacksLegacyPass : public ModulePass {
public:
  static char ID;

  FunctionPrivateStacksLegacyPass() : ModulePass(ID) {
    initializeFunctionPrivateStacksLegacyPassPass(*PassRegistry::getPassRegistry());
  }

  bool runOnModule(Module &M) override {
    // NHM-FIXME: check per-function flag.
    if (!EnableFunctionPrivateStacks)
      return false;

    FunctionPrivateStacks FPS(M);
    return FPS.run();
  }
};

char FunctionPrivateStacksLegacyPass::ID = 0;

}

INITIALIZE_PASS(FunctionPrivateStacksLegacyPass, "ir-fps", "Function-Private Stacks IR Pass", false, false)

ModulePass *llvm::createFunctionPrivateStacksPass() { return new FunctionPrivateStacksLegacyPass(); }
