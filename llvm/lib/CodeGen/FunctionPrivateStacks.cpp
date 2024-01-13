#include "llvm/CodeGen/FunctionPrivateStacks.h" // NHM-TODO: Maybe don't need this?

#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/InitializePasses.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

namespace llvm {

// NHM-FIXME: Fixup flags.
cl::opt<bool> EnableFunctionPrivateStacks(
    "x86-function-private-stacks", cl::init(false), cl::Hidden);
}

namespace {

class FunctionPrivateStacks {
  Module &M;
  LLVMContext &Ctx;
  bool Changed;
  IntegerType *Int64Ty;
  PointerType *PtrTy;
  FunctionCallee RegStack;
  FunctionCallee DeregStack;
  
  void runOnFunction(Function &F, IRBuilder<> &CtorIRB, IRBuilder<> &DtorIRB);
  
public:
  FunctionPrivateStacks(Module &M) : M(M), Ctx(M.getContext()), Changed(false) {}
  bool run();
};

void FunctionPrivateStacks::runOnFunction(Function &F, IRBuilder<> &CtorIRB, IRBuilder<> &DtorIRB) {
  // NHM-FIXME: Assert only works on 64-bit architectures.

  // NHM-FIXME: Should this always have private linkage?
  auto *StackIdxVar = new GlobalVariable(M, Int64Ty, /*isConstant*/false, GlobalVariable::InternalLinkage, Constant::getNullValue(Int64Ty) , "__fps_stackidx_" + F.getName());
  Constant *FnNameExpr = ConstantDataArray::getString(Ctx, F.getName(), true);
  Constant *FnName = new GlobalVariable(M, FnNameExpr->getType(), /*isConsatnt*/true, GlobalVariable::PrivateLinkage, FnNameExpr);
  
  

  // Register stack.
  Value *StackIdx = CtorIRB.CreateCall(RegStack, {FnName});
  CtorIRB.CreateStore(StackIdx, StackIdxVar);

  // Deregister stack.
  DtorIRB.CreateCall(DeregStack, {DtorIRB.CreateLoad(Int64Ty, StackIdxVar), FnName});
}

bool FunctionPrivateStacks::run() {
  Int64Ty = IntegerType::get(Ctx, 64);
  PtrTy = PointerType::getUnqual(Ctx);
    
  // Declare thread-local variable.
  new GlobalVariable(M, PointerType::getUnqual(Ctx), /*isConstant*/false, GlobalVariable::ExternalLinkage, nullptr, "__fps_thd_stackptrs");
  new GlobalVariable(M, PointerType::getUnqual(Ctx), /*isConstant*/false, GlobalVariable::ExternalLinkage, nullptr, "__fps_thd_stackbases");
  new GlobalVariable(M, IntegerType::get(Ctx, 64), /*isConstant*/false, GlobalVariable::ExternalLinkage, nullptr, "__fps_thd_stacksizes");

  auto *CtorTy = FunctionType::get(Type::getVoidTy(Ctx), {}, /*isVarArg*/false);
  auto *Ctor = Function::Create(CtorTy, Function::InternalLinkage, "__fps_regstack_ctor", M);
  IRBuilder<> CtorIRB(BasicBlock::Create(Ctx, "", Ctor));
  auto *Dtor = Function::Create(CtorTy, Function::InternalLinkage, "__fps_regstack_dtor", M);
  IRBuilder<> DtorIRB(BasicBlock::Create(Ctx, "", Dtor));

  RegStack = Function::Create(FunctionType::get(Int64Ty, {PtrTy}, /*isVarArg*/false), Function::ExternalLinkage, "__fps_regstack", M);
  DeregStack = Function::Create(FunctionType::get(Type::getVoidTy(Ctx), {Int64Ty, PtrTy}, /*isVarArg*/false), Function::ExternalLinkage, "__fps_deregstack", M);
  
  for (Function &F : M)
    if (!F.isDeclaration() && !F.getName().startswith("__fps_"))
      runOnFunction(F, CtorIRB, DtorIRB);

  CtorIRB.CreateRetVoid();
  DtorIRB.CreateRetVoid();

  appendToGlobalCtors(M, Ctor, 0);
  appendToGlobalDtors(M, Dtor, 0);

#if 0
  interceptPthreadCreate();
#endif
  
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
