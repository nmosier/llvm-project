#ifndef LLVM_CODEGEN_TARGETFUNCTIONPRIVATESTACKS_H
#define LLVM_CODEGEN_TARGETFUNCTIONPRIVATESTACKS_H

#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/MC/MCRegister.h"

namespace llvm {

class LivePhysRegs;

class TargetFunctionPrivateStacks : public MachineFunctionPass {
protected:
  const MCPhysReg PSPReg;
  const MCPhysReg FlagsReg;
  const TargetRegisterClass &ScratchRC;

  TargetFunctionPrivateStacks(char &ID, MCPhysReg PSPReg, MCPhysReg FlagsReg, const TargetRegisterClass &ScratchRC)
      : MachineFunctionPass(ID), PSPReg(PSPReg), FlagsReg(FlagsReg), ScratchRC(ScratchRC) {}

  bool runOnMachineFunction(MachineFunction &MF) final;

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
      MachineFunction &MF,
      SmallVectorImpl<MachineInstr *> &PrivateFrameAccesses,
      Align &PrivateFrameAlign);

  bool
  frameIndexOnlyUsedInMemoryOperands(int FI, MachineFunction &MF,
                                     SmallVectorImpl<MachineOperand *> &Uses);

  void assignRegsForPrivateStackPointer(
      MachineFunction &MF, ArrayRef<MachineInstr *> Uses);

  void emitPrologue(MachineFunction &MF, unsigned PrivateFrameSize);
  void emitEpilogue(MachineFunction &MF, unsigned PrivateFrameSize);
  virtual bool instrumentSetjmps(MachineFunction &MF) = 0; // NHM-FIXME: Should be de-virtualized.

  const TargetRegisterClass *computeAddrBaseRegClass(ArrayRef<const MachineOperand *> Uses) const;

  void loadPrivateStackPointer(
      MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Reg);

  virtual void loadPrivateStackPointerLeaf(MachineBasicBlock &MBB,
                                           MachineBasicBlock::iterator MBBI,
                                           Register Reg) = 0;

  virtual void emitPrologueCheck(MachineBasicBlock &CheckMBB,
                                 std::array<MCPhysReg, 2> Regs,
                                 unsigned PrivateFrameSize) = 0;
  virtual void emitPrologueAlloc(MachineBasicBlock &AllocMBB,
                                 std::array<MCPhysReg, 2> Regs,
                                 const uint32_t *RegMask) = 0;
  virtual MachineOperand getCondEqualMO() const = 0;
  virtual void emitEpilogueImpl(MachineBasicBlock &MBB,
                                MachineBasicBlock::iterator MBBI,
                                std::array<MCPhysReg, 2> Regs) = 0;

  virtual void loadRegFromBaseReg(MachineBasicBlock &MBB,
                                  MachineBasicBlock::iterator MBBI,
                                  Register Dest, Register Src) const = 0;

  virtual bool needScratchForPointerToFPSData() const = 0;
  virtual void getPointerToFPSData(MachineBasicBlock &MBB,
                                   MachineBasicBlock::iterator MBBI,
                                   const GlobalVariable *Member,
                                   MCPhysReg DestReg,
                                   MCPhysReg ScratchReg) const = 0;
  void loadPrivateStackPointerFull(MachineBasicBlock &MBB,
                                   MachineBasicBlock::iterator MBBI,
                                   Register Reg) const;

  MCPhysReg getScratchReg(const LivePhysRegs &LPR,
                          ArrayRef<MCPhysReg> Blacklist = {}) const;
  MCPhysReg getScratchReg(const MachineBasicBlock &MBB,
                          MachineBasicBlock::const_iterator MBBI,
                          ArrayRef<MCPhysReg> Blacklist = {}) const;
};

} // namespace llvm 

#endif