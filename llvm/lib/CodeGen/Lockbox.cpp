#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/Pass.h"
#include "llvm/InitializePasses.h"
#include "llvm/IR/IntrinsicsX86.h"

using namespace llvm;

namespace {

class Lockbox {
  Function &F;
  Module &M;
  LLVMContext &Ctx;

public:
  Lockbox(Function &F) : F(F), M(*F.getParent()), Ctx(M.getContext()) {}
  bool run();
};

}

bool Lockbox::run() {
  // Is this a lockbox function?
  if (!F.hasFnAttribute(Attribute::Lockbox)) {
    return false;
  }

  // Is this function only called directly and has local linkage?
  if (!F.hasAddressTaken() && F.hasLocalLinkage()) {
    return false;
  }

  // Since this function may be called indirectly or externally,
  // insert code to enable pkey protections.
  // NOTE: The pkey is stored in __lockbox_pkey.
  auto *Int32Ty = IntegerType::get(Ctx, 32);
  auto *VoidTy = Type::getVoidTy(Ctx);                     
  GlobalVariable *pkey =
      cast<GlobalVariable>(M.getOrInsertGlobal("__lockbox_pkey", Int32Ty, [&]() -> GlobalVariable * {
        return new GlobalVariable(M, Int32Ty, /*isConstant*/ false,
                                  GlobalVariable::ExternalLinkage,
                                  /*Initializer*/ nullptr, "__lockbox_pkey");
      }));

  // Enable access on call. 
  BasicBlock &EntryBB = F.getEntryBlock();
  IRBuilder<> IRB(&EntryBB, EntryBB.getFirstNonPHIOrDbgOrAlloca());
  Value *OldPKRU = IRB.CreateIntrinsic(Int32Ty, Intrinsic::x86_rdpkru, {});
  Value *Mask = IRB.CreateShl(IRB.getInt32(0b11), pkey);
  Mask = IRB.CreateNot(Mask);
  Value *NewPKRU = IRB.CreateAnd(OldPKRU, Mask);
  IRB.CreateIntrinsic(VoidTy, Intrinsic::x86_wrpkru, {NewPKRU});

  
  report_fatal_error("NHM-TODO: stub");
}

namespace {

class LockboxLegacyPass : public FunctionPass {
public:
  static char ID;

  LockboxLegacyPass() : FunctionPass(ID) {
    initializeLockboxLegacyPassPass(*PassRegistry::getPassRegistry());
  }

  bool runOnFunction(Function &F) override {
    Lockbox LB(F);
    return LB.run();
  }
};

char LockboxLegacyPass::ID = 0;

} // namespace

INITIALIZE_PASS(LockboxLegacyPass, "ir-lockbox", "Lockbox IR Pass", false,
                false)

FunctionPass *llvm::createLockboxPass() { return new LockboxLegacyPass(); }
