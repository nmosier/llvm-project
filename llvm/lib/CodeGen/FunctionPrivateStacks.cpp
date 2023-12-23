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
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/ADT/SmallSet.h"

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
  enum {
    kSize,
    kBasePtr,
    kStackPtr,
    kNext,
    kPrev,
    kNumFields
  };
  StructType *StackStructTy;
  FunctionCallee RegisterStackCallee, DeregisterStackCallee;
  
  Constant *UnsafeStackPtrVar;

  bool requiresPrivateStack(const Function &F) const;
  void createPrivateStack(Function &F);
  void declareRuntimeInterface();
  void moveUnsafeAllocations(Function &F);

  // NHM-FIXME: Get rid of this.
  struct StackVars {
    GlobalVariable *BasePtr;
    GlobalVariable *Size;
    GlobalVariable *StackPtr;
  };

  StackVars createStack(GlobalValue::LinkageTypes Linkage, Constant *Data, function_ref<Twine (StringRef)> Name);
};

#if 0
FunctionPrivateStacks::StackVars FunctionPrivateStacks::createStack(
    GlobalValue::LinkageTypes Linkage, Constant *Data, function_ref<Twine (StringRef)> GetName) {
  auto CreateStackVar = [&] (StringRef VarName, Type *Ty) -> GlobalVariable * {
    const std::string Name = GetName(VarName).str();
    assert(!M.getNamedValue(Name) && "Stack variable already exists!\n");
    return new GlobalVariable(M, Ty, /*isConstant*/false, Linkage, nullptr, Name);
  };
  StackVars Vars;
  PointerType *PtrTy = PointerType::getUnqual(Ctx);
  Vars.BasePtr = CreateStackVar("baseptr", PtrTy);
  Vars.Size = CreateStackVar("size", Type::getInt32Ty(Ctx));
  Vars.Size->setInitializer(Constant::getNullValue(Vars.Size->getValueType()));
  Vars.StackPtr = CreateStackVar("stackptr", PtrTy);

  Type *VoidTy = Type::getVoidTy(Ctx);
  FunctionType *FTy = FunctionType::get(VoidTy, {PtrTy, PtrTy}, false);
  
  // Create constructor.
  Function *Ctor = Function::Create(FTy, Linkage, GetName("ctor").str(), M);
  Ctor->setLinkage(Linkage);
  BasicBlock *CtorBB = BasicBlock::Create(Ctx, "", Ctor);
  IRBuilder<> CtorIRB(CtorBB);
  CtorIRB.CreateCall(AllocStack, {Vars.BasePtr, Vars.Size});
  Value *StackPtrVal = CtorIRB.CreateGEP(CtorIRB.getInt8Ty(), Vars.BasePtr, {Vars.Size});
  CtorIRB.CreateStore(StackPtrVal, Vars.StackPtr);
  // NHM-FIXME: Need to make sure there's a guard page above?
  CtorIRB.CreateRetVoid();
  // NHM-FIXME: Need speculation fence.
  appendToGlobalCtors(M, Ctor, 0, Data);  

  // Create destructor.
  Function *Dtor = Function::Create(FTy, Linkage, GetName("dtor").str(), M);
  BasicBlock *DtorBB = BasicBlock::Create(Ctx, "", Dtor);
  IRBuilder<> DtorIRB(DtorBB);
  DtorIRB.CreateCall(FreeStack, {Vars.BasePtr, Vars.Size});
  DtorIRB.CreateRetVoid();
  appendToGlobalDtors(M, Dtor, 0, Data);

  return Vars;
}
#endif

void FunctionPrivateStacks::run() {
  PointerType *PtrTy = PointerType::getUnqual(Ctx);

  // Create stack struct type.
  std::array<Type *, kNumFields> StackElements;
  std::fill(StackElements.begin(), StackElements.end(), nullptr);
  StackElements[kSize] = Type::getInt64Ty(Ctx);
  StackElements[kBasePtr] = PtrTy;
  StackElements[kStackPtr] = PtrTy;
  StackElements[kNext] = PtrTy;
  StackElements[kPrev] = PtrTy;
  StackStructTy = StructType::get(Ctx, StackElements);

  // Declare stack registry functions.
  FunctionType *RegFuncTy = FunctionType::get(Type::getVoidTy(Ctx), {PtrTy}, /*isVarArg*/false);
  RegisterStackCallee = M.getOrInsertFunction("__fps_register", RegFuncTy);
  DeregisterStackCallee = M.getOrInsertFunction("__fps_deregister", RegFuncTy);

  // Get unsafe stack pointer.
  GlobalVariable *UnsafeStackVar = new GlobalVariable(M, StackStructTy, /*isConstant*/false, GlobalVariable::ExternalLinkage, nullptr, "__fps_unsafestack", nullptr, GlobalVariable::GeneralDynamicTLSModel, /*isExternallyInitialized*/true);
  UnsafeStackPtrVar = ConstantExpr::getGetElementPtr(StackStructTy, UnsafeStackVar, {ConstantInt::get(Type::getInt32Ty(Ctx), kStackPtr)});

  // Create registry function.
  FunctionType *RegModTy = FunctionType::get(Type::getVoidTy(Ctx), /*isVarArg*/false);
  auto CreateRegFn = [&] (StringRef Name, auto CtorFn, IRBuilder<>& IRB) {
    Function *F = Function::Create(RegModTy, Function::InternalLinkage, Name, M);
    BasicBlock *B = BasicBlock::Create(Ctx, "", F);
    IRB.SetInsertPoint(B);
    Instruction *Ret = IRB.CreateRetVoid();
    IRB.SetInsertPoint(Ret);
    CtorFn(M, F, 0, nullptr);
  };
  IRBuilder<> RegIRB(Ctx);
  CreateRegFn("__fps_register_module", appendToGlobalCtors, RegIRB);
  IRBuilder<> DeregIRB(Ctx);
  CreateRegFn("__fps_deregister_module", appendToGlobalDtors, DeregIRB);
  
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;

    if (!F.hasFnAttribute(Attribute::FunctionPrivateStack))
      continue;

    // Create a new private stack.
    const std::string Name = ("__fps_stack_" + F.getName()).str();
    std::array<Constant *, kNumFields> StackVarMembs;
    llvm::transform(StackElements, StackVarMembs.begin(), [] (Type *T) -> Constant * {
      return Constant::getNullValue(T);
    });
    GlobalVariable *StackVar = new GlobalVariable(M, StackStructTy, /*isConstant*/false, GlobalVariable::InternalLinkage, ConstantStruct::get(StackStructTy, StackVarMembs), Name);

    // Register stack.
    RegIRB.CreateCall(RegisterStackCallee, {StackVar});

    // Deregister stack.
    DeregIRB.CreateCall(DeregisterStackCallee, {StackVar});


    // Move unsafe stack allocations to unsafe stack.
    moveUnsafeAllocations(F);
  }

}

bool isSafeAllocaInst(const AllocaInst &Alloca) {
  return Alloca.isStaticAlloca() && Alloca.getAlign().value() <= 4096;
}

void FunctionPrivateStacks::moveUnsafeAllocations(Function &F) {
  // NHM-FIXME: Not handling C++ execptions.
  
  SmallSet<AllocaInst *, 4> UnsafeAllocas;
  SmallVector<ReturnInst *> Returns;
  for (Instruction &I : instructions(F)) {
    auto *Alloc = dyn_cast<AllocaInst>(&I);
    if (Alloc && !isSafeAllocaInst(*Alloc)) {
      UnsafeAllocas.insert(Alloc);
    }
    if (auto *Ret = dyn_cast<ReturnInst>(&I)) {
      Returns.push_back(Ret);
    }
  }

  if (UnsafeAllocas.empty())
    return;

  IRBuilder<> IRB(Ctx);
  for (Instruction& I : F.getEntryBlock()) {
    IRB.SetInsertPoint(&I);
    if (UnsafeAllocas.contains(dyn_cast<AllocaInst>(&I)))
      break;
  }
  LoadInst *OrigUnsafeStackPtr = IRB.CreateLoad(PointerType::getUnqual(Ctx), UnsafeStackPtrVar);
  
  for (AllocaInst *Alloc : UnsafeAllocas) {
    IRB.SetInsertPoint(Alloc);
    Value *UnsafeStackPtr = OrigUnsafeStackPtr;
    UnsafeStackPtr = IRB.CreateGEP(Alloc->getAllocatedType(), UnsafeStackPtr, {IRB.getInt32(-1)});
    UnsafeStackPtr = IRB.CreatePtrToInt(UnsafeStackPtr, IRB.getInt64Ty());
    UnsafeStackPtr = IRB.CreateAnd(UnsafeStackPtr, ~((static_cast<uint64_t>(1) << Alloc->getAlign().value()) - 1));
    UnsafeStackPtr = IRB.CreateIntToPtr(UnsafeStackPtr, PointerType::getUnqual(Ctx));
    IRB.CreateStore(UnsafeStackPtr, UnsafeStackPtrVar);
    Alloc->replaceAllUsesWith(UnsafeStackPtr);
    Alloc->eraseFromParent();
  }

  // Restore stack pointer on return.
  for (Instruction *I : Returns) {
    IRB.SetInsertPoint(I);
    IRB.CreateStore(OrigUnsafeStackPtr, UnsafeStackPtrVar);
  }
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

namespace {

class FunctionPrivateStacksMachinePass : public MachineFunctionPass {
public:
  static char ID;
  
  FunctionPrivateStacksMachinePass(): MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &MF) override;
  
private:
};

char FunctionPrivateStacksMachinePass::ID = 0;

bool FunctionPrivateStacksMachinePass::runOnMachineFunction(MachineFunction &MF) {
  
  
  return true;
}

}
