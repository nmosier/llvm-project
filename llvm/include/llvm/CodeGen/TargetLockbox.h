#ifndef LLVM_CODEGEN_TARGETLOCKBOX_H
#define LLVM_CODEGEN_TARGETLOCKBOX_H

#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/MC/TargetRegistry.h"

namespace llvm {

class LivePhysRegs;

class TargetLockbox : public MachineFunctionPass {
  const bool IsIndirectControlSafe;
  const unsigned MaskBitWidth;
protected:
  const TargetRegisterClass &ScratchRC;

  const DebugLoc Loc;
  const TargetInstrInfo *TII = nullptr;
  const TargetRegisterInfo *TRI = nullptr;
  const MachineRegisterInfo *MRI = nullptr;
  const GlobalVariable *MaskEnableSym = nullptr;
  const GlobalVariable *MaskDisableSym = nullptr;

  using ProgramPoint =
      std::pair<MachineBasicBlock *, MachineBasicBlock::iterator>;

  virtual void emitAccess(MachineBasicBlock &MBB,
                          MachineBasicBlock::iterator MBBI, bool IsEnable) = 0;

  MCPhysReg getScratchReg(const LivePhysRegs &LPR, ArrayRef<MCPhysReg> Ignore = {}) const;
  MCPhysReg getScratchReg(const MachineBasicBlock &MBB, MachineBasicBlock::const_iterator MBBI, ArrayRef<MCPhysReg> Ignore = {}) const;

private:

  using ProgramPointVec = SmallVectorImpl<ProgramPoint>;

  bool isDisableAccessPoint(const MachineInstr &MI) const;

  void identifyDisableAccessPoints(MachineFunction &MF,
                                   ProgramPointVec &Out);
  void identifyEnableAccessPoints(MachineFunction &MF,
                                  ProgramPointVec &Out);
  void instrumentFunction(MachineFunction &MF, ProgramPointVec &EnablePoints,
                          ProgramPointVec &DisablePoints);

  
public:
  TargetLockbox(char &ID, bool IsIndirectControlSafe, unsigned MaskBitWidth, const TargetRegisterClass &ScratchRC)
      : MachineFunctionPass(ID), IsIndirectControlSafe(IsIndirectControlSafe), MaskBitWidth(MaskBitWidth), ScratchRC(ScratchRC) {}
  
  bool runOnMachineFunction(MachineFunction &MF) final;
};

}

#endif