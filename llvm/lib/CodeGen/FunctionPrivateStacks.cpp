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
  StructType *RegInfoTy;
  
  void runOnFunction(Function &F, std::vector<Constant *> &RegInfos);
  
public:
  FunctionPrivateStacks(Module &M) : M(M), Ctx(M.getContext()), Changed(false) {}
  bool run();
};

void FunctionPrivateStacks::runOnFunction(Function &F, std::vector<Constant *> &RegInfos) {
  // NHM-FIXME: Assert only works on 64-bit architectures.

  // NHM-FIXME: Should this always have private linkage?
  auto *StackIdxVar = new GlobalVariable(M, Int64Ty, /*isConstant*/false, GlobalVariable::InternalLinkage, Constant::getNullValue(Int64Ty) , "__fps_stackidx_" + F.getName());
  Constant *FnNameExpr = ConstantDataArray::getString(Ctx, F.getName(), true);
  Constant *FnName = new GlobalVariable(M, FnNameExpr->getType(), /*isConsatnt*/true, GlobalVariable::PrivateLinkage, FnNameExpr);
  auto *FrameSize = new GlobalVariable(M, Int64Ty, /*isConstant*/true, GlobalVariable::InternalLinkage, ConstantInt::get(Int64Ty, 42) /* NHM-FIXME */, "__fps_framesize_" + F.getName());
  auto *DummyFrame = new GlobalVariable(M, PtrTy, /*isConstant*/false, GlobalVariable::InternalLinkage, Constant::getNullValue(PtrTy), "__fps_dummy_" + F.getName());
  RegInfos.push_back(ConstantStruct::get(RegInfoTy, StackIdxVar, FnName, FrameSize, DummyFrame));

#if 0
  // Register stack.
  Value *StackIdx = CtorIRB.CreateCall(RegStack, {FnName});
  CtorIRB.CreateStore(StackIdx, StackIdxVar);

  // Deregister stack.
  DtorIRB.CreateCall(DeregStack, {DtorIRB.CreateLoad(Int64Ty, StackIdxVar), FnName});
#endif
}

bool FunctionPrivateStacks::run() {
  Int64Ty = IntegerType::get(Ctx, 64);
  PtrTy = PointerType::getUnqual(Ctx);

  // struct reginfo {
  //   uintptr_t *index;
  //   const char *name;
  //   const uintptr_t *private_frame_size;
  //   const void **dummy_frame;
  RegInfoTy = StructType::get(PtrTy, PtrTy, PtrTy, PtrTy);

  // Declare thread-local variable.
  // NHM-FIXME: Not sure if these are necessary at this point.
  new GlobalVariable(M, PointerType::getUnqual(Ctx), /*isConstant*/false, GlobalVariable::ExternalLinkage, nullptr, "__fps_thd_stacks");

  auto *CtorTy = FunctionType::get(Type::getVoidTy(Ctx), {}, /*isVarArg*/false);
  auto *Ctor = Function::Create(CtorTy, Function::InternalLinkage, "__fps_regstack_ctor", M);
  IRBuilder<> CtorIRB(BasicBlock::Create(Ctx, "", Ctor));
  auto *Dtor = Function::Create(CtorTy, Function::InternalLinkage, "__fps_regstack_dtor", M);
  IRBuilder<> DtorIRB(BasicBlock::Create(Ctx, "", Dtor));


  std::vector<Constant *> RegInfos;
  
  for (Function &F : M)
    if (!F.isDeclaration() && !F.getName().starts_with("__fps_"))
      runOnFunction(F, RegInfos);

  Constant *RegInfoArr = ConstantArray::get(ArrayType::get(RegInfoTy, RegInfos.size()), RegInfos);
  auto *RegInfoVar = new GlobalVariable(M, RegInfoArr->getType(), /*isConstant*/true, GlobalVariable::PrivateLinkage, RegInfoArr);

  FunctionType *RegTy = FunctionType::get(Type::getVoidTy(Ctx), {Int64Ty, PtrTy}, /*isVarArg*/false);
  FunctionCallee RegStacks = Function::Create(RegTy, Function::ExternalLinkage, "__fps_regstacks", M);
  CtorIRB.CreateCall(RegStacks, {CtorIRB.getInt64(RegInfos.size()), RegInfoVar});
  CtorIRB.CreateRetVoid();

  FunctionCallee DeregStacks = Function::Create(RegTy, Function::ExternalLinkage, "__fps_deregstacks", M);
  DtorIRB.CreateCall(DeregStacks, {DtorIRB.getInt64(RegInfos.size()), RegInfoVar});
  DtorIRB.CreateRetVoid();

  appendToGlobalCtors(M, Ctor, 0);
  appendToGlobalDtors(M, Dtor, 0);

  // NHM-FIXME: If there are no FPSes, then just skip.

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
