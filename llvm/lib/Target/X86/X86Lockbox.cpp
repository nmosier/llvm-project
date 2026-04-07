#include "MCTargetDesc/X86MCTargetDesc.h"
#include "X86.h"
#include "X86RegisterInfo.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/TargetLockbox.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/Pass.h"
#include "llvm/CodeGen/TargetInstrInfo.h"

#define PASS_KEY "x86-lockbox"
#define DEBUG_TYPE PASS_KEY

using namespace llvm;

namespace {

class X86Lockbox final : public TargetLockbox {
public:
  static inline char ID = 0;

  X86Lockbox() : TargetLockbox(ID, false, 32, X86::GR64RegClass) {
    initializeX86LockboxPass(*PassRegistry::getPassRegistry());
  }

private:
  void emitAccess(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, bool IsEnable) override;
};

void X86Lockbox::emitAccess(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI,
                     bool IsEnable) {
  // MOV ecx, 0
  // RDPKRU  ; implicitly into eax
  // OR/AND eax, [__lockbox_mask_{enable,disable}]
  // WRPKRU ; implicitly from eax
  const GlobalVariable *MaskSym = IsEnable ? MaskEnableSym : MaskDisableSym;
  const unsigned MergeOpcode = IsEnable ? X86::AND32rm : X86::OR32rm;

  // MOV ecx, 0
  BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV32r0), X86::ECX);
  // RDPKRU
  BuildMI(MBB, MBBI, Loc, TII->get(X86::RDPKRUr));
  // OR/AND eax, [__lockbox_mask_{enable,disable}]
  BuildMI(MBB, MBBI, Loc, TII->get(MergeOpcode), X86::EAX)
      .addReg(X86::EAX)
      .addReg(X86::RIP)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addGlobalAddress(MaskSym)
      .addReg(X86::NoRegister);
  // WRPKRU
  BuildMI(MBB, MBBI, Loc, TII->get(X86::WRPKRUr));
}

} // namespace

INITIALIZE_PASS(X86Lockbox, PASS_KEY, "X86 Lockbox", false, false)

FunctionPass *llvm::createX86LockboxPass() { return new X86Lockbox(); }