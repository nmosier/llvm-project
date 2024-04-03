#include "X86.h"
#include "X86Subtarget.h"
#include "llvm/CodeGen/LivePhysRegs.h"

// NHM-FIXME: Rename
// NHM-FIXME: inherit from shared class.

using namespace llvm;

#define PASS_KEY "x86-cfind2"
#define DEBUG_TYPE PASS_KEY

namespace {

class X86ControlFlowIndirectionPass2 : public MachineFunctionPass {
public:
  X86ControlFlowIndirectionPass2() : MachineFunctionPass(ID) {}
  static char ID;
  StringRef getPassName() const override {
    return "X86 Control-Flow Indirection Pass 2";
  }
  bool runOnMachineFunction(MachineFunction &MF) override;

private:
  const TargetInstrInfo *TII;
  const TargetRegisterInfo *TRI;

  void handleConditional(MachineBasicBlock &MBB);
};

}

char X86ControlFlowIndirectionPass2::ID = 0;

bool X86ControlFlowIndirectionPass2::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "***** " << getPassName() << " : " << MF.getName() << " *****\n");
  TII = MF.getSubtarget().getInstrInfo();
  TRI = MF.getSubtarget().getRegisterInfo();

  bool Changed = false;

  for (MachineBasicBlock &MBB : MF) {
    if (llvm::any_of(MBB.terminators(), [] (const MachineInstr &MI) {
      return MI.isConditionalBranch();
    })) {
      handleConditional(MBB);
      Changed = true;
    }
  }

  return Changed;
}

void X86ControlFlowIndirectionPass2::handleConditional(MachineBasicBlock &MBB) {
  assert(std::distance(MBB.terminators().begin(), MBB.terminators().end()) == 1);
  MachineInstr &CondBr = MBB.back();
  assert(CondBr.isConditionalBranch());
  MachineBasicBlock *Fallthrough = MBB.getFallThrough();
  assert(Fallthrough);
  assert(CondBr.getOpcode() == X86::JCC_1);
  const MachineRegisterInfo &MRI = MBB.getParent()->getRegInfo();
  
  // Find two free registers.
  LivePhysRegs LPR(*TRI);
  LPR.addLiveOuts(MBB);
  LPR.stepBackward(CondBr);
  SmallVector<Register> Regs;
  for (Register Reg : X86::GR64RegClass)
    if (LPR.available(MRI, Reg))
      Regs.push_back(Reg);
  if (Regs.size() < 2) {
    report_fatal_error("not enough free registers!");
  }

  DebugLoc Loc;
  auto MBBI = CondBr.getIterator();

  auto InsertLEA = [&] (Register Reg ,MachineBasicBlock *Target) {
    BuildMI(MBB, MBBI, Loc, TII->get(X86::LEA64r), Reg)
        .addReg(X86::RIP)
        .addImm(1)
        .addReg(X86::NoRegister)
        .addMBB(Target)
        .addReg(X86::NoRegister);
    Target->setMachineBlockAddressTaken();
  };

  InsertLEA(Regs[0], Fallthrough);
  InsertLEA(Regs[1], CondBr.getOperand(0).getMBB());
  BuildMI(MBB, MBBI, Loc, TII->get(X86::CMOV64rr), Regs[0])
      .addReg(Regs[0])
      .addReg(Regs[1])
      .addImm(CondBr.getOperand(1).getImm());
  BuildMI(MBB, MBBI, Loc, TII->get(X86::JMP64r))
      .addReg(Regs[0]);

  CondBr.eraseFromParent();
}

INITIALIZE_PASS(X86ControlFlowIndirectionPass2, PASS_KEY, "X86 control-flow indirection pass 2", false, false)
FunctionPass *llvm::createX86ControlFlowIndirectionPass2() {
  return new X86ControlFlowIndirectionPass2();
}
