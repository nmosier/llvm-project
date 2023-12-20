#include "llvm/CodeGen/FunctionPrivateStacks.h"

#include <vector>

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Pass.h"
#include "llvm/InitializePasses.h"
#include "llvm/CodeGen/Passes.h"

using namespace llvm;

#define DEBUG_TYPE "fps"

namespace {

class FunctionPrivateStacks {
public:
  FunctionPrivateStacks(Module &M) : Ctx(M.getContext()), M(M) {}
  void run();
private:
  LLVMContext &Ctx;
  Module &M;
  FunctionCallee AllocStack, FreeStack;

  bool requiresPrivateStack(const Function &F) const;
  void createPrivateStack(Function &F);
  void declareRuntimeInterface();
};

void FunctionPrivateStacks::run() {
  declareRuntimeInterface();
  std::vector<Function *> Funcs;
  for (Function &F : M)
    if (requiresPrivateStack(F))
      Funcs.push_back(&F);
  for (Function *F : Funcs)
    createPrivateStack(*F);
}

bool FunctionPrivateStacks::requiresPrivateStack(const Function &F) const {
  if (F.isDeclaration())
    return false;

  // Check if it is already a private stack constructor/destructor.
  if (F.getName().starts_with("__fps_ctor_") || F.getName().starts_with("__fps_dtor_"))
    return false;

  return true;
}

void FunctionPrivateStacks::declareRuntimeInterface() {
  PointerType *PtrTy = PointerType::getUnqual(Ctx);
  FunctionType *FTy = FunctionType::get(Type::getVoidTy(Ctx), {PtrTy, PtrTy}, /*isVarArg*/false);
  AllocStack = M.getOrInsertFunction("__fps_allocstack", FTy);
  FreeStack = M.getOrInsertFunction("__fps_freestack", FTy);
}

void FunctionPrivateStacks::createPrivateStack(Function &F) {
  if (F.isDeclaration())
    return;

  auto CreateVar = [&] (const std::string& Name, Type *Ty) -> Constant * {
    auto *Var = cast<GlobalVariable>(M.getOrInsertGlobal(Name, Ty, [&] () {
      return new GlobalVariable(M, Ty, /*isConstant*/false, F.getLinkage(), nullptr, Name);
    }));
    if (!Var->hasInitializer())
      Var->setInitializer(Constant::getNullValue(Ty));
    return Var;
  };
  Constant *BasePtrVar = CreateVar(("__fps_baseptr_" + F.getName()).str(), PointerType::getUnqual(Ctx));
  Constant *SizeVar = CreateVar(("__fps_size_" + F.getName()).str(), Type::getInt32Ty(Ctx));
  Type *IdxTy = Type::getInt32Ty(Ctx);
  Constant *IdxVar = CreateVar(("__fps_idx_" + F.getName()).str(), IdxTy);

  // Create constructor.
  Type *VoidTy = Type::getVoidTy(Ctx);
  Function *Ctor = cast<Function>(
      M.getOrInsertFunction(
          ("__fps_ctor_" + F.getName()).str(), AttributeList(),
          VoidTy).getCallee());
  BasicBlock *CtorBB = BasicBlock::Create(Ctx, "", Ctor);
  IRBuilder<> CtorIRB(CtorBB);
  // NHM-FIXME: Should initialize size, optionally at least?
  CtorIRB.CreateCall(AllocStack, {BasePtrVar, SizeVar});
  CtorIRB.CreateStore(ConstantInt::get(IdxTy, 0), IdxVar);
  CtorIRB.CreateRetVoid();
  // NHM-FIXME: Need speculation fence.
  appendToGlobalCtors(M, Ctor, 0, &F);

  // Create destructor.
  Function *Dtor = cast<Function>(
      M.getOrInsertFunction(
          ("__fps_dtor_" + F.getName()).str(), AttributeList(),
          VoidTy).getCallee());
  BasicBlock *DtorBB = BasicBlock::Create(Ctx, "", Dtor);
  IRBuilder<> DtorIRB(DtorBB);
  DtorIRB.CreateCall(FreeStack, {BasePtrVar, SizeVar});
  DtorIRB.CreateRetVoid();
  appendToGlobalDtors(M, Dtor, 0, &F);
}

}

namespace llvm {

PreservedAnalyses FunctionPrivateStacksPass::run(Module &M, ModuleAnalysisManager &) {
  FunctionPrivateStacks FPSPass(M);
  FPSPass.run();
  return PreservedAnalyses::none();
}

}

namespace {

class FunctionPrivateStacksLegacyPass : public ModulePass {
public:
  static char ID;

  FunctionPrivateStacksLegacyPass() : ModulePass(ID) {
    initializeFunctionPrivateStacksLegacyPassPass(*PassRegistry::getPassRegistry());
  }

  bool runOnModule(Module &M) override {
    FunctionPrivateStacks FPSPass(M);
    FPSPass.run();
    return true; // NHM-FIXME: Is this true?
  }
};

char FunctionPrivateStacksLegacyPass::ID = 0;

}

INITIALIZE_PASS(FunctionPrivateStacksLegacyPass, DEBUG_TYPE, "Function-Private Stacks instrumentation pass", false, false)

ModulePass *llvm::createFunctionPrivateStacksPass() { return new FunctionPrivateStacksLegacyPass(); }
