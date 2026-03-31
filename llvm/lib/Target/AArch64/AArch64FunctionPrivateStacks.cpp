#include "AArch64.h"
#include "AArch64InstrInfo.h"
#include "AArch64RegisterInfo.h"
#include "AArch64RegisterInfo.h"
#include "AArch64Subtarget.h"
#include "MCTargetDesc/AArch64MCTargetDesc.h"
#include "Utils/AArch64BaseInfo.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/PseudoSourceValue.h"
#include "llvm/CodeGen/TargetFrameLowering.h"
#include "llvm/CodeGen/TargetFunctionPrivateStacks.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/Support/DebugLog.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/TypeSize.h"

using namespace llvm;

#define PASS_KEY "aarch64-fps"
#define DEBUG_TYPE PASS_KEY

namespace {

class AArch64FunctionPrivateStacks final : public TargetFunctionPrivateStacks {
public:
  static char ID;

  AArch64FunctionPrivateStacks()
      : TargetFunctionPrivateStacks(ID, AArch64::X15, AArch64::NZCV,
                                    AArch64::GPR64RegClass) {
    initializeAArch64FunctionPrivateStacksPass(
        *PassRegistry::getPassRegistry());
  }

private:
  bool hasBasePointer(const MachineFunction &MF) const override {
    return static_cast<const AArch64RegisterInfo *>(TRI())->hasBasePointer(MF);
  }

  const AArch64InstrInfo *TII() const {
    return static_cast<const AArch64InstrInfo *>(this->TargetFunctionPrivateStacks::TII);
  }

  const AArch64RegisterInfo *TRI() const {
    return static_cast<const AArch64RegisterInfo *>(this->TargetFunctionPrivateStacks::TRI);
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
    if (&BaseMO != &MO)
      return false;
    // Finally, check if this has a displacement operand.
    // If not, bail. We could support this in the future, though,
    // by rewriting it.
    // NOTE: Got this list from the implementation of
    // llvm::isAArch64FrameOffsetLegal
    if (!doesLdStHaveImmOffset(MI.getOpcode()))
      return false;

    return true;
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

  void loadPrivateStackPointerLeaf(MachineBasicBlock &MBB,
                                   MachineBasicBlock::iterator MBBI,
                                   Register Reg) override;

  void emitPrologueCheck(MachineBasicBlock &CheckMBB,
                         std::array<MCPhysReg, 2> Regs,
                         unsigned PrivateFrameSize) override;
  void emitPrologueAlloc(MachineBasicBlock &AllocMBB,
                         std::array<MCPhysReg, 2> Regs,
                         const uint32_t *RegMask) override;
  void emitEpilogueImpl(MachineBasicBlock &MBB,
                        MachineBasicBlock::iterator MBBI,
                        std::array<MCPhysReg, 2> Regs) override;
  void loadRegFromBaseReg(MachineBasicBlock &MBB,
                          MachineBasicBlock::iterator MBBI, Register Dest,
                          Register Src) const override;

  void fixupPrivateStackAccess(MachineInstr &MI) override {
    // NHM-FIXME: Should eliminate this entirely, eventually.
    LDBG() << "not fixing up private stack access";

#if 0
    LDBG() << "before: " << MI;

    for (const MachineOperand &MO : MI.operands()) {
      if (MO.isFI()) {
        int FI = MO.getIndex();
        // NHM-FIXME: This is just for debugging, so remove later.
        if (MFI->getStackID(FI) != TargetStackID::PrivateStack)
          continue;
        assert(MFI->getStackID(FI) == TargetStackID::PrivateStack);
        TRI()->eliminateFrameIndex(MI.getIterator(), /*SPAdj*/0, MO.getOperandNo(), nullptr);
      }
    }

    LDBG() << "after: " << MI;

    // Remove any FixedStackPseudoSourceValue MachineMemOperands.
    if (!MI.hasOneMemOperand())
      return;

    const MachineMemOperand *MMO = *MI.memoperands_begin();
    const PseudoSourceValue *PSV = MMO->getPseudoValue();
    if (!PSV || !isa<FixedStackPseudoSourceValue>(PSV))
      return;

    MI.setMemRefs(*MI.getParent()->getParent(), {});
    LDBG() << "removing FixedStackPseudoSourceValue memory operand from stack spill instruction";
#endif
  }
};

} // namespace

// NHM-FIXME: Remove scratch reg interface!
void AArch64FunctionPrivateStacks::getPointerToFPSData(
    MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI,
    const GlobalVariable *Member, MCPhysReg DestReg,
    MCPhysReg ScratchReg) const {
  // AArch64 equivalent of the X86 implementation:
  //   adrp  dest,   :gottpoff:Member@page
  //   ldr   dest,   [dest, :gottpoff_lo12:Member]
  //   mrs   scratch, tpidr_el0
  //   ldr   dest, [dest, scratch] ; returns pointer __fps_thd_stacks
  //   adrp  scratch, StackIdxSym@page
  //   ldr   scratch, [scratch, :lo12:StackIdxSym]
  //   add   dest,   dest, scratch         ; dest += *StackIdxSym

  // Load TLS offset of Member from GOT (initial-exec / GOTTPOFF).
  // ADRP and LDR must use the same register so that linker IE→LE relaxation
  // emits MOVZ+MOVK to a single register rather than splitting them.
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::ADRP), DestReg)
      .addGlobalAddress(Member, 0, AArch64II::MO_TLS | AArch64II::MO_PAGE);
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::LDRXui), DestReg)
      .addReg(DestReg)
      .addGlobalAddress(Member, 0,
                        AArch64II::MO_TLS | AArch64II::MO_PAGEOFF |
                            AArch64II::MO_NC);

  // Add thread pointer to get the actual TLS address of Member.
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::MRS), ScratchReg)
      .addImm(AArch64SysReg::TPIDR_EL0);
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::LDRXroX), DestReg)
      .addReg(ScratchReg)
      .addReg(DestReg)
      .addImm(0)
      .addImm(0);

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

void AArch64FunctionPrivateStacks::loadPrivateStackPointerLeaf(
    MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Reg) {

  // AArch64 equivalent of the X86 initial-exec TLS load:
  //   adrp scratch, :gottpoff:FPSSym@page
  //   ldr  Reg,    [scratch, :gottpoff_lo12:FPSSym]  ; TLS offset of FPSSym
  //   mrs  scratch, tpidr_el0                         ; thread pointer (== fs:[0] on x86)
  //   add  Reg,    Reg, scratch                       ; TLS address of FPSSym

  // Find a free scratch register.
  // NHM-FIXME: This should be shared with TargetFPS's code.
  LivePhysRegs LPR(*TRI());
  LPR.addLiveOuts(MBB);
  for (auto It = MBB.rbegin(); It != MBB.rend(); ++It) {
    LPR.stepBackward(*It);
    if (It->getIterator() == MBBI)
      break;
  }
  MCPhysReg ScratchReg = MCRegister::NoRegister;
  for (MCPhysReg R : AArch64::GPR64RegClass) {
    if (LPR.available(*MRI, R) && R != Reg) {
      ScratchReg = R;
      break;
    }
  }
  assert(ScratchReg != MCRegister::NoRegister &&
         "No scratch register available for loadPrivateStackPointerLeaf");

  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::ADRP), ScratchReg)
      .addGlobalAddress(FPSSym, 0, AArch64II::MO_TLS | AArch64II::MO_PAGE);
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::LDRXui), ScratchReg)
      .addReg(ScratchReg)
      .addGlobalAddress(FPSSym, 0,
                        AArch64II::MO_TLS | AArch64II::MO_PAGEOFF |
                            AArch64II::MO_NC);
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::MRS), Reg)
      .addImm(AArch64SysReg::TPIDR_EL0);
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::ADDXrr), Reg)
      .addReg(Reg)
      .addReg(ScratchReg);
}

void AArch64FunctionPrivateStacks::emitPrologueCheck(
    MachineBasicBlock &CheckMBB, std::array<MCPhysReg, 2> Regs,
    unsigned PrivateFrameSize) {
  // AArch64 lacks memory-operand arithmetic, so we need a third scratch
  // register to load current_frame->next before comparing.
  LivePhysRegs LPR(*TRI());
  LPR.addLiveIns(CheckMBB);
  MCPhysReg TmpReg = getScratchReg(LPR, {Regs[0], Regs[1]});

  // fps_t *Regs[0] = <TLS address of ThdStacksSym>;
  // (Uses Regs[1] as scratch for the multi-instruction TLS address sequence.)
  getPointerToFPSData(CheckMBB, CheckMBB.end(), ThdStacksSym, Regs[0], Regs[1]);

  // frame_t *Tmp = Regs[0]->current_frame;
  BuildMI(CheckMBB, CheckMBB.end(), Loc, TII()->get(AArch64::LDRXui), TmpReg)
      .addReg(Regs[0])
      .addImm(0); // offsetof_fps_current_frame = 0 (scaled: 0/8 = 0)

  // frame_t *Regs[1] = Tmp->next;  (offsetof_frame_next = -8)
  BuildMI(CheckMBB, CheckMBB.end(), Loc, TII()->get(AArch64::LDURXi), Regs[1])
      .addReg(TmpReg)
      .addImm(-8); // offsetof_frame_next = -8 (unscaled byte offset)

  // bool overflow = (Regs[1] == TmpReg);
  BuildMI(CheckMBB, CheckMBB.end(), Loc, TII()->get(AArch64::SUBSXrs),
          AArch64::XZR)
      .addReg(Regs[1])
      .addReg(TmpReg)
      .addImm(0); // no shift

  // Regs[0]->current_frame = Regs[1];
  BuildMI(CheckMBB, CheckMBB.end(), Loc, TII()->get(AArch64::STRXui))
      .addReg(Regs[1])
      .addReg(Regs[0])
      .addImm(0); // offsetof_fps_current_frame = 0 (scaled: 0/8 = 0)
}

void AArch64FunctionPrivateStacks::emitPrologueAlloc(
    MachineBasicBlock &AllocMBB, std::array<MCPhysReg, 2> Regs,
    const uint32_t *RegMask) {
  // AllocMBB:
  //   X0 = *StackIdxSym   (load the stack index for this function)
  //   bl __fps_morestack
  //
  // AArch64 uses X0 as the first argument register (analogous to X86's RDI).
  // Load the value at StackIdxSym via ADRP + LDR (non-TLS, plain global).
  BuildMI(AllocMBB, AllocMBB.end(), DebugLoc(), TII()->get(AArch64::ADRP),
          AArch64::X0)
      .addGlobalAddress(StackIdxSym, 0, AArch64II::MO_PAGE);
  BuildMI(AllocMBB, AllocMBB.end(), DebugLoc(), TII()->get(AArch64::LDRXui),
          AArch64::X0)
      .addReg(AArch64::X0)
      .addGlobalAddress(StackIdxSym, 0, AArch64II::MO_PAGEOFF | AArch64II::MO_NC);
  BuildMI(AllocMBB, AllocMBB.end(), DebugLoc(), TII()->get(AArch64::BL))
      .addExternalSymbol("__fps_morestack")
      .addRegMask(RegMask)
      .addUse(AArch64::X0, RegState::ImplicitKill);
  MFI->setAdjustsStack(true);
  MFI->setHasCalls(true);
}

void AArch64FunctionPrivateStacks::emitEpilogueImpl(
    MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI,
    std::array<MCPhysReg, 2> Regs) {
  // fps_t *Regs[0] = <TLS address of ThdStacksSym>;
  // frame_t *Regs[1] = Regs[0]->current_frame;
  // Regs[1] = Regs[1]->prev;
  // Regs[0]->current_frame = Regs[1];
  //
  // AArch64's getPointerToFPSData needs a scratch register. Regs[1] (PSPReg)
  // is used as scratch and gets clobbered, so we re-load current_frame from
  // fps.current_frame rather than relying on PSPReg to hold it directly.

  // Regs[0] = &fps_data  (Regs[1] used as scratch, gets clobbered)
  getPointerToFPSData(MBB, MBBI, ThdStacksSym, Regs[0], Regs[1]);

  // Regs[1] = fps_data.current_frame  (offsetof_fps_current_frame = 0, scaled)
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::LDRXui), Regs[1])
      .addReg(Regs[0])
      .addImm(0);

  // Regs[1] = current_frame->prev  (offsetof_frame_prev = -16, unscaled)
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::LDURXi), Regs[1])
      .addReg(Regs[1])
      .addImm(-16);

  // fps_data.current_frame = Regs[1]  (offsetof_fps_current_frame = 0, scaled)
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::STRXui))
      .addReg(Regs[1])
      .addReg(Regs[0])
      .addImm(0);
}

void AArch64FunctionPrivateStacks::loadRegFromBaseReg(
    MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Dest,
    Register Src) const {
  BuildMI(MBB, MBBI, Loc, TII()->get(AArch64::LDRXui), Dest)
      .addReg(Src)
      .addImm(0);
}


INITIALIZE_PASS(AArch64FunctionPrivateStacks, PASS_KEY,
                "AArch64 Function Private Stacks", false, false)

FunctionPass *llvm::createAArch64FunctionPrivateStacksPass() {
  return new AArch64FunctionPrivateStacks();
}

char AArch64FunctionPrivateStacks::ID = 0;