#include "MCTargetDesc/X86MCTargetDesc.h"
#include "X86.h"
#include "X86RegisterInfo.h"
#include "llvm/ADT/MapVector.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/TargetLockbox.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/Pass.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/Support/DebugLog.h"

#define PASS_KEY "x86-lockbox"
#define DEBUG_TYPE PASS_KEY

using namespace llvm;

namespace {

class X86Lockbox final : public TargetLockbox {
public:
  static inline char ID = 0;
  bool Lower;

  X86Lockbox(bool Lower)
      : TargetLockbox(ID, false, 32, X86::GR64RegClass),
        Lower(Lower) {
    initializeX86LockboxPass(*PassRegistry::getPassRegistry());
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

private:
  void emitAccess(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI,
                  bool IsEnable) override;
  void lowerAccess(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI,
                   bool IsEnable);
  bool doLowering(MachineFunction &MF);
  bool shouldOptimizeAccesses() const override { return false; }

  MCPhysReg getLargestLiveReg(MCPhysReg Reg, const LivePhysRegs &LPR) const;
};

MCPhysReg X86Lockbox::getLargestLiveReg(MCPhysReg Reg,
                                        const LivePhysRegs &LPR) const {
  MCPhysReg LiveReg = X86::NoRegister;
  for (MCPhysReg SubReg : TRI->sub_and_superregs_inclusive(Reg)) {
    if (!LPR.contains(SubReg))
      continue;
    if (LiveReg && TRI->isSubRegisterEq(LiveReg, SubReg))
      continue;
    LiveReg = SubReg;
  }
  return LiveReg;
}

void X86Lockbox::lowerAccess(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI,
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

void X86Lockbox::emitAccess(MachineBasicBlock &MBB,
                            MachineBasicBlock::iterator MBBI, bool IsEnable) {
  LDBG() << "Emitting access at " << *MBBI;
  
  LivePhysRegs LPR(*TRI);
  LPR.addLiveOuts(MBB);
  for (const MachineInstr &MI : llvm::reverse(MBB)) {
    LPR.stepBackward(MI);
    if (MI.getIterator() == MBBI)
      break;
  }

  // Save any registers (EAX/ECX/EDX) that would be clobbered.
  for (MCPhysReg Reg : {X86::EAX, X86::ECX, X86::EDX}) {
    Reg = getLargestLiveReg(Reg, LPR);
    if (!Reg)
      continue;
    auto *RC = TRI->getMinimalPhysRegClass(Reg);
    RC = TRI->getLargestLegalSuperClass(RC, *MBB.getParent());
    Register TmpReg = MRI->createVirtualRegister(RC);
    BuildMI(MBB, MBBI, Loc, TII->get(X86::COPY), TmpReg)
                      .addReg(Reg, RegState::Kill);
    auto &Restore = *BuildMI(MBB, MBBI, Loc, TII->get(X86::COPY), Reg)
                         .addReg(TmpReg);
    MBBI = Restore.getIterator();
    LDBG() << "Saved/restored " << TRI->getRegAsmName(Reg);
  }

  const unsigned Opcode = IsEnable ? X86::LOCKBOX_ENABLE : X86::LOCKBOX_DISABLE;
  MachineInstr &MI = *BuildMI(MBB, MBBI, Loc, TII->get(Opcode));
  // Mark all outputs as dead.
  for (MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isDef())
      MO.setIsDead();
  LDBG() << "inserted instruction: " << MI;
}

bool X86Lockbox::runOnMachineFunction(MachineFunction &MF) {
  TII = MF.getSubtarget().getInstrInfo();
  if (Lower) {
    initialize(MF);
    return doLowering(MF);
  }
  return TargetLockbox::runOnMachineFunction(MF);
}

static bool hasLockboxOpcode(const MachineInstr &MI) {
  switch (MI.getOpcode()) {
  default:
    return false;
  case X86::LOCKBOX_ENABLE:
  case X86::LOCKBOX_DISABLE:
    return true;
  }
}

bool X86Lockbox::doLowering(MachineFunction &MF) {
  for (MachineBasicBlock &MBB : MF) {
    // Convert back to MBBIs.
    AccessPointVec MBBIs;
    auto AddMBBI = [&](MachineBasicBlock::iterator MBBI, bool IsEnable) {
      for (; MBBI != MBB.end() && hasLockboxOpcode(*MBBI); ++MBBI) {
      }
      MBBIs.emplace_back(MBBI, IsEnable);
    };

    for (MachineInstr &MI : llvm::make_early_inc_range(MBB)) {
      bool IsEnable;
      switch (MI.getOpcode()) {
      case X86::LOCKBOX_ENABLE:
        IsEnable = true;
        break;
      case X86::LOCKBOX_DISABLE:
        IsEnable = false;
        break;
      default:
        continue;
      }

      AddMBBI(MI.getIterator(), IsEnable);
      MI.eraseFromParent();
    }

    LDBG() << "Optimizing accesses (" << MBBIs.size() << ")";

    optimizeAccesses(MBB, MBBIs);

    for (auto [MBBI, IsEnable] : MBBIs)
      lowerAccess(MBB, MBBI, IsEnable);
  }
  return true;
}

} // namespace

INITIALIZE_PASS(X86Lockbox, PASS_KEY, "X86 Lockbox", false, false)

FunctionPass *llvm::createX86LockboxPass(bool Lower) { return new X86Lockbox(Lower); }