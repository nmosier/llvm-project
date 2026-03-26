#ifndef LLVM_CODEGEN_FUNCTIONPRIVATESTACKSMIR_H
#define LLVM_CODEGEN_FUNCTIONPRIVATESTACKSMIR_H

#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/MC/MCRegister.h"

namespace llvm {

class TargetFunctionPrivateStacks : public MachineFunctionPass {
protected:
  const MCPhysReg PSPReg;

  TargetFunctionPrivateStacks(char &ID, MCPhysReg PSPReg) : MachineFunctionPass(ID), PSPReg(PSPReg) {}

  bool runOnMachineFunction(MachineFunction &MF) override;

  const TargetInstrInfo *TII;
  const TargetRegisterInfo *TRI;
  MachineFrameInfo *MFI;
  MachineRegisterInfo *MRI;

  DebugLoc Loc;

  // Symbols.
  GlobalVariable *StackIdxSym;
  GlobalVariable *ThdStacksSym;
  GlobalVariable *FrameSizeSym;
  GlobalVariable *FPSSym;

  virtual bool hasBasePointer(const MachineFunction &MF) const = 0;

  uint64_t collectPrivateFrameObjects(
      MachineFunction &MF, DenseMap<int, uint64_t> &PrivateFrameInfo,
      SmallVectorImpl<MachineInstr *> &PrivateFrameAccesses);

  bool
  frameIndexOnlyUsedInMemoryOperands(int FI, MachineFunction &MF,
                                     SmallVectorImpl<MachineOperand *> &Uses);

  virtual bool checkFrameIndex(const MachineOperand &MO) const = 0;

  virtual void assignRegsForPrivateStackPointer(
      MachineFunction &MF, ArrayRef<MachineInstr *> Uses,
      const DenseMap<int, uint64_t> &PrivateFrameInfo) = 0; // NHM-FIXME: Should be de-virtualized.

  virtual void emitPrologue(MachineFunction &MF, unsigned PrivateFrameSize) = 0; // NHM-FIXME: Should be de-virtualized.
  virtual void emitEpilogue(MachineFunction &MF, unsigned PrivateFrameSize) = 0; // NHM-FIXME: Should be de-virtualized.
  virtual bool instrumentSetjmps(MachineFunction &MF) = 0; // NHM-FIXME: Should be de-virtualized.

  virtual const TargetRegisterClass *computeAddrBaseRegClass(ArrayRef<const MachineOperand *> Uses) = 0; // NHM-FIXME: Should be de-virtualized.



};

}

#endif