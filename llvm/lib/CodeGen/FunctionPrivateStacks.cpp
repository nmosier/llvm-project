#include "llvm/CodeGen/FunctionPrivateStacks.h" // NHM-TODO: Maybe don't need this?

#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Support/DebugLog.h"

#define PASS_KEY "fps"
#define DEBUG_TYPE PASS_KEY

using namespace llvm;

namespace llvm {

// NHM-FIXME: Fixup flags.
// NHM-FIXME: Can make static.
cl::opt<bool> EnableLeafFPS(PASS_KEY "-leaf", cl::init(true),
                            cl::Hidden);
STATISTIC(FullFPSCount, "Number of functions with a full FPS");
STATISTIC(LeafFPSCount, "Number of functions with a leaf FPS");

cl::opt<bool> EnableFPSStrictMode(
    PASS_KEY "-strict", cl::init(false), cl::Hidden,
    cl::desc("Enable strict mode for function private stacks, which enforces "
             "that security requirements are met."));

} // namespace llvm

static cl::opt<bool> EnableFPS(PASS_KEY "-enable", cl::init(true), cl::Hidden);

namespace {

class FunctionPrivateStacks {
  Module &M;
  LLVMContext &Ctx;
  IntegerType *Int64Ty;
  PointerType *PtrTy;
  StructType *RegInfoTy;
  
  void runOnFunction(Function &F, std::vector<Constant *> &RegInfos);
  void runOnFunctionFull(Function &F, std::vector<Constant *> &RegInfos);
  void runOnFunctionLeaf(Function &F);
  GlobalVariable *createFrameSize(Function &F);
  
public:
  FunctionPrivateStacks(Module &M) : M(M), Ctx(M.getContext()) {}
  bool run();
};

GlobalVariable *FunctionPrivateStacks::createFrameSize(Function &F) {
  return new GlobalVariable(M, Int64Ty, /*isConstant*/ true,
                            GlobalVariable::InternalLinkage,
                            ConstantInt::get(Int64Ty, 0),
                            "__fps_framesize_" + F.getName());
}



void FunctionPrivateStacks::runOnFunctionFull(Function &F, std::vector<Constant *> &RegInfos) {
  // NHM-FIXME: Should this always have private linkage?
  auto *StackIdxVar = new GlobalVariable(M, Int64Ty, /*isConstant*/false, GlobalVariable::InternalLinkage, Constant::getNullValue(Int64Ty) , "__fps_stackidx_" + F.getName());
  Constant *FnNameExpr = ConstantDataArray::getString(Ctx, F.getName(), true);
  Constant *FnName =
      new GlobalVariable(M, FnNameExpr->getType(), /*isConsatnt*/ true,
                         GlobalVariable::PrivateLinkage, FnNameExpr);
  auto *FrameSize = createFrameSize(F);
  RegInfos.push_back(ConstantStruct::get(RegInfoTy, StackIdxVar, FnName, FrameSize));
}

void FunctionPrivateStacks::runOnFunctionLeaf(Function &F) {
  // NOTE: We don't do anything here, since the machine IR FPS pass is
  // responsible for creating the thread-local FPS frame.
}

void FunctionPrivateStacks::runOnFunction(Function &F, std::vector<Constant *> &RegInfos) {
  // NHM-FIXME: Assert only works on 64-bit architectures.

  // Compute the FPS kind.
  if (EnableLeafFPS && F.doesNotRecurse()) {
    F.setFPSKind(Function::LeafFPS);
    LDBG() << "Leaf FPS for " << F.getName();
    ++LeafFPSCount;
  } else {
    F.setFPSKind(Function::FullFPS);
    LDBG() << "Full FPS for " << F.getName();
    ++FullFPSCount;
  }

  switch (F.fpsKind()) {
    case Function::FullFPS:
      runOnFunctionFull(F, RegInfos);
      break;
    case Function::LeafFPS:
      runOnFunctionLeaf(F);
      break;
    default:
      report_fatal_error("unimplemented: unhandled FPS kind");
  }
}

bool FunctionPrivateStacks::run() {
  if (!EnableFPS)
    return false;

  // Do any functions in this module require a private stack?
  // If not, don't do anything.
  if (none_of(M, [](const Function &F) -> bool {
    return !F.isDeclaration() && F.hasFnAttribute(Attribute::FunctionPrivateStack);
  })) {
    return false;
  }
  
  Int64Ty = IntegerType::get(Ctx, 64);
  PtrTy = PointerType::getUnqual(Ctx);

  // struct reginfo {
  //   uintptr_t *index;
  //   const char *name;
  //   const uintptr_t *private_frame_size;
  RegInfoTy = StructType::get(PtrTy, PtrTy, PtrTy);

  // Declare thread-local variable.
  // NHM-FIXME: Not sure if these are necessary at this point.
  new GlobalVariable(M, PointerType::getUnqual(Ctx), /*isConstant*/false, GlobalVariable::ExternalLinkage, nullptr, "__fps_thd_stacks", nullptr, GlobalVariable::InitialExecTLSModel);

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

  return true;
}

class FunctionPrivateStacksLegacyPass : public ModulePass {
public:
  static char ID;

  FunctionPrivateStacksLegacyPass() : ModulePass(ID) {
    initializeFunctionPrivateStacksLegacyPassPass(*PassRegistry::getPassRegistry());
  }

  bool runOnModule(Module &M) override {
    FunctionPrivateStacks FPS(M);
    return FPS.run();
  }
};

char FunctionPrivateStacksLegacyPass::ID = 0;

}

INITIALIZE_PASS(FunctionPrivateStacksLegacyPass, "ir-fps", "Function-Private Stacks IR Pass", false, false)

ModulePass *llvm::createFunctionPrivateStacksPass() { return new FunctionPrivateStacksLegacyPass(); }
