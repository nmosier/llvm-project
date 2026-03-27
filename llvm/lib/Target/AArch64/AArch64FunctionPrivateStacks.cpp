#include "AArch64.h"
#include "AArch64InstrInfo.h"
#include "AArch64RegisterInfo.h"
#include "AArch64RegisterInfo.h"
#include "AArch64Subtarget.h"
#include "MCTargetDesc/AArch64MCTargetDesc.h"
#include "Utils/AArch64BaseInfo.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/TargetFunctionPrivateStacks.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/Support/ErrorHandling.h"

using namespace llvm;

#define PASS_KEY "aarch64-fps"
#define DEBUG_TYPE PASS_KEY

namespace {

class AArch64FunctionPrivateStacks final : public TargetFunctionPrivateStacks {
public:
  static char ID;

  AArch64FunctionPrivateStacks()
      : TargetFunctionPrivateStacks(ID, PSPReg, AArch64::NZCV,
                                    AArch64::GPR64RegClass) {
    initializeAArch64FunctionPrivateStacksPass(
        *PassRegistry::getPassRegistry());
  }

private:
  bool hasBasePointer(const MachineFunction &MF) const override {
    return static_cast<const AArch64RegisterInfo *>(TRI)->hasBasePointer(MF);
  }

  const AArch64InstrInfo *TII() const {
    return static_cast<const AArch64InstrInfo *>(this->TargetFunctionPrivateStacks::TII);
  }

  const MachineOperand &getLdStBaseOp(const MachineInstr &MI) const {
    return TII()->getLdStBaseOp(MI);
  }

  unsigned getLdStBaseIdx(const MachineInstr &MI) const {
    return getLdStBaseOp(MI).getOperandNo();
  }

  MachineOperand &getLdStBaseOp(MachineInstr &MI) const {
    return MI.getOperand(getLdStBaseIdx(MI));
  }

  const MachineOperand &getLdStOffsetOp(const MachineInstr &MI) const {
    return TII()->getLdStOffsetOp(MI);
  }

  unsigned getLdStOffsetIdx(const MachineInstr &MI) const {
    return getLdStOffsetOp(MI).getOperandNo();
  }

  MachineOperand &getLdStOffsetOp(MachineInstr &MI) const {
    return MI.getOperand(getLdStOffsetIdx(MI));
  }

  // NHM-FIXME: This could be made less redundant.
  bool checkFrameIndex(const MachineOperand &MO) const override {
    const MachineInstr &MI = *MO.getParent();
    if (!MI.mayLoadOrStore())
      return false;
    const MachineOperand &BaseMO = getLdStBaseOp(MI);
    return &BaseMO == &MO;
  }

  bool instrumentSetjmps(MachineFunction &MF) override {
    // NHM-FIXME: Should handle external setjmps at least...
    return false;
  }

  MachineOperand &getAddrBaseOp(MachineInstr &MI) const override {
    return getLdStBaseOp(MI);
  }
  MachineOperand &getAddrDispOp(MachineInstr &MI) const override {
    return getLdStOffsetOp(MI);
  }

  MachineOperand getCondEqualMO() const override {
    return MachineOperand::CreateImm(AArch64CC::EQ);
  }

  bool needScratchForPointerToFPSData() const override { return true; }

  void getPointerToFPSData(MachineBasicBlock &MBB,
                           MachineBasicBlock::iterator MBBI,
                           const GlobalVariable *Member, MCPhysReg DestReg,
                           MCPhysReg ScratchReg) const override;
};

} // namespace

void AArch64FunctionPrivateStacks::getPointerToFPSData(
    MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI,
    const GlobalVariable *Member, MCPhysReg DestReg,
    MCPhysReg ScratchReg) const {
  // AArch64 equivalent of the X86 implementation:
  //   adrp  scratch, :gottpoff:Member@page
  //   ldr   dest,   [scratch, :gottpoff_lo12:Member]
  //   mrs   scratch, tpidr_el0
  //   add   dest,   dest, scratch         ; dest = TLS address of Member
  //   adrp  scratch, StackIdxSym@page
  //   ldr   scratch, [scratch, :lo12:StackIdxSym]
  //   add   dest,   dest, scratch         ; dest += *StackIdxSym

  // Load TLS offset of Member from GOT (initial-exec / GOTTPOFF).
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::ADRP), ScratchReg)
      .addGlobalAddress(Member, 0, AArch64II::MO_TLS | AArch64II::MO_PAGE);
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::LDRXui), DestReg)
      .addReg(ScratchReg)
      .addGlobalAddress(Member, 0,
                        AArch64II::MO_TLS | AArch64II::MO_PAGEOFF |
                            AArch64II::MO_NC);

  // Add thread pointer to get the actual TLS address of Member.
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::MRS), ScratchReg)
      .addImm(AArch64SysReg::TPIDR_EL0);
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::ADDXrr), DestReg)
      .addReg(DestReg)
      .addReg(ScratchReg);

  // Add *StackIdxSym.
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::ADRP), ScratchReg)
      .addGlobalAddress(StackIdxSym, 0, AArch64II::MO_PAGE);
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::LDRXui), ScratchReg)
      .addReg(ScratchReg)
      .addGlobalAddress(StackIdxSym, 0,
                        AArch64II::MO_PAGEOFF | AArch64II::MO_NC);
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::ADDXrr), DestReg)
      .addReg(DestReg)
      .addReg(ScratchReg);
}

INITIALIZE_PASS(AArch64FunctionPrivateStacks, PASS_KEY,
                "AArch64 Function Private Stacks", false, false)

FunctionPass *llvm::createAArch64FunctionPrivateStacksPass() {
#if 0
  return new AArch64FunctionPrivateStacks();
#else
  report_fatal_error("TODO");
#endif
}

char AArch64FunctionPrivateStacks::ID = 0;