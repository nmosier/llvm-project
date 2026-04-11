#include "AArch64.h"
#include "AArch64RegisterInfo.h"
#include "MCTargetDesc/AArch64MCTargetDesc.h"
#include "Utils/AArch64BaseInfo.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/TargetLockbox.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/MC/MCRegister.h"

#define PASS_KEY "aarch64-lockbox"
#define DEBUG_TYPE PASS_KEY

using namespace llvm;

namespace {

class AArch64Lockbox final : public TargetLockbox {
public:
  static inline char ID = 0;

  AArch64Lockbox() : TargetLockbox(ID, true, 64, AArch64::GPR64RegClass) {
    initializeAArch64LockboxPass(*PassRegistry::getPassRegistry());
  }

private:
  void emitAccess(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI,
                  bool IsEnable) override;
  bool shouldOptimizeAccesses() const override { return true; }
};

void AArch64Lockbox::emitAccess(MachineBasicBlock &MBB,
                                    MachineBasicBlock::iterator MBBI,
                                    bool IsEnable) {
  // MRS Reg1, POR_EL0
  // ADRP Reg2, __lockbox_mask_{enable,disable}@page
  // LDR Reg2, [Reg2, __lockbox_mask_{enable,disable}@lo12]
  // OR/AND Reg1, Reg2
  // MSR POR_EL0, Reg1

  const MCPhysReg Reg1 = getScratchReg(MBB, MBBI, {});
  const MCPhysReg Reg2 = getScratchReg(MBB, MBBI, {Reg1});
  const GlobalVariable *MaskSym = IsEnable ? MaskEnableSym : MaskDisableSym;
  const unsigned MergeOpcode = IsEnable ? AArch64::ORRXrr : AArch64::ANDXrr;

  BuildMI(MBB, MBBI, Loc, TII->get(AArch64::MRS), Reg1)
      .addImm(AArch64SysReg::TPIDR_EL0);
  BuildMI(MBB, MBBI, Loc, TII->get(AArch64::ADRP), Reg2)
      .addGlobalAddress(MaskSym, 0, AArch64II::MO_PAGE);
  BuildMI(MBB, MBBI, Loc, TII->get(AArch64::LDRXui), Reg2)
      .addReg(Reg2)
      .addGlobalAddress(MaskSym, 0, AArch64II::MO_PAGEOFF | AArch64II::MO_NC);
  BuildMI(MBB, MBBI, Loc, TII->get(MergeOpcode), Reg1)
      .addReg(Reg1)
      .addReg(Reg2);
  BuildMI(MBB, MBBI, Loc, TII->get(AArch64::MSR))
      .addReg(Reg1)
      .addImm(AArch64SysReg::TPIDR_EL0);
}

} // namespace

INITIALIZE_PASS(AArch64Lockbox, PASS_KEY, "AArch64 Lockbox", false, false)

FunctionPass *llvm::createAArch64LockboxPass() { return new AArch64Lockbox(); }