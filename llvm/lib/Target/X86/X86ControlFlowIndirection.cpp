// NHM-FIXME: Rename appropriately.OA
#include "X86.h"
#include "X86Subtarget.h"
#include "llvm/ADT/STLExtras.h"

using namespace llvm;

#define PASS_KEY "x86-cfind"
#define DEBUG_TYPE PASS_KEY

namespace {

class X86ControlFlowIndirectionPass final : public MachineFunctionPass {
public:
  X86ControlFlowIndirectionPass() : MachineFunctionPass(ID) {}
  static char ID;
  StringRef getPassName() const override {
    return "X86 Control-Flow Indirection Pass";
  }
  bool runOnMachineFunction(MachineFunction &MF) override;

private:
  const TargetInstrInfo *TII;
  
  void handleConditional(MachineBasicBlock &MBB);
};

}

char X86ControlFlowIndirectionPass::ID = 0;

bool X86ControlFlowIndirectionPass::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "***** " << getPassName() << " : " << MF.getName() << " *****\n");
  TII = MF.getSubtarget().getInstrInfo();

  bool Changed = false;

  for (MachineBasicBlock &MBB : MF) {
    if (llvm::any_of(MBB.terminators(), [] (const MachineInstr &MI) {
      return MI.isConditionalBranch();
    })) {
      handleConditional(MBB);
      Changed = true;
    }

    for (MachineInstr &MI : MBB) {
      if (MI.isCall() && !MI.isReturn()) {
        assert(!MI.isTerminator());
        BuildMI(MBB, std::next(MI.getIterator()), DebugLoc(), TII->get(X86::LFENCE));
      }
    }
  }

  MF.verify();

  return Changed;
}

void X86ControlFlowIndirectionPass::handleConditional(MachineBasicBlock &MBB) {
  struct CondBrInfo {
    int Cond; // one of X86::COND_*
    MachineBasicBlock *Target;
  };

  SmallVector<CondBrInfo> CondBrInfos;
  for (MachineInstr &MI : MBB.terminators()) {
    if (!MI.isConditionalBranch())
      break;
    if (MI.getOpcode() == X86::EH_SjLj_Setup) {
      LLVM_DEBUG(dbgs() << "warning: EH_SjLj_Setup unhandled\n");
      return;
    }
      
    assert(MI.getOpcode() == X86::JCC_1);
    CondBrInfo CBI;
    CBI.Cond = MI.getOperand(1).getImm();
    CBI.Target = MI.getOperand(0).getMBB();
    CondBrInfos.push_back(CBI);
  }

  MachineBasicBlock::iterator MBBI = MBB.terminators().begin();
  DebugLoc Loc;  

  auto MakeVReg = [&] () -> Register {
    return MBB.getParent()->getRegInfo().createVirtualRegister(&X86::GR64RegClass);
  };

  auto InsertLEA = [&] (MachineBasicBlock *Target) -> Register {
    Register Reg = MakeVReg();
    BuildMI(MBB, MBBI, Loc, TII->get(X86::LEA64r), Reg)
        .addReg(X86::RIP)
        .addImm(1)
        .addReg(X86::NoRegister)
        .addMBB(Target)
        .addReg(X86::NoRegister);
    Target->setMachineBlockAddressTaken();
    return Reg;
  };

  MachineBasicBlock *Fallthrough = MBB.getLogicalFallThrough();
  if (!Fallthrough) {
    MachineInstr &UncondBr = MBB.back();
    assert(UncondBr.isUnconditionalBranch());
    assert(llvm::count_if(UncondBr.operands(), std::mem_fn(&MachineOperand::isMBB)) == 1);
    const auto MBBIt = llvm::find_if(UncondBr.operands(), std::mem_fn(&MachineOperand::isMBB));
    Fallthrough = MBBIt->getMBB();
  }
  assert(Fallthrough);
  Register Reg = InsertLEA(Fallthrough);
  for (const CondBrInfo &CBI : CondBrInfos) {
    Register LEAReg = InsertLEA(CBI.Target);
    Register CMovReg = MakeVReg();
    BuildMI(MBB, MBBI, Loc, TII->get(X86::CMOV64rr), CMovReg)
        .addReg(Reg)
        .addReg(LEAReg)
        .addImm(CBI.Cond);
    Reg = CMovReg;
  }
  // BuildMI(MBB, MBBI, Loc, TII->get(X86::LFENCE)); // NHM-FIXME: don't fence this?
  BuildMI(MBB, MBBI, Loc, TII->get(X86::JMP64r))
      .addReg(Reg);

  for (auto it = MBBI; it != MBB.end(); ++it) {
    assert(!it->getPreInstrSymbol() && !it->getPostInstrSymbol());
  }
    
  MBB.erase(MBBI, MBB.end());

  LLVM_DEBUG(dbgs() << "[condbr -> indbr] after: " << MBB);
}

INITIALIZE_PASS(X86ControlFlowIndirectionPass, PASS_KEY, "X86 control-flow indirection pass", false, false)
FunctionPass *llvm::createX86ControlFlowIndirectionPass() {
  return new X86ControlFlowIndirectionPass();
}
