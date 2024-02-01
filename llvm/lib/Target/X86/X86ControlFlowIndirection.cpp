// NHM-FIXME: Rename appropriately.OA
#include "X86.h"
#include "X86Subtarget.h"
#include "llvm/ADT/STLExtras.h"

using namespace llvm;

#define PASS_KEY "x86-cfind"
#define DEBUG_TYPE PASS_KEY

namespace {

class X86ControlFlowIndirectionPass : public MachineFunctionPass {
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
  void handleIndirect(MachineBasicBlock &MBB);
  void handleReturn(MachineBasicBlock &MBB);
};

}

char X86ControlFlowIndirectionPass::ID = 0;

bool X86ControlFlowIndirectionPass::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "***** " << getPassName() << " : " << MF.getName() << " *****\n");
  TII = MF.getSubtarget().getInstrInfo();

#if 0
  // First, split multiple JCCs into saeparate blocks.
  for (MachineBasicBlock &MBB : llvm::make_early_inc_range(MF)) {
    auto Terminators = MBB.terminators();
    const auto NumTerminators = std::distance(Terminators.begin(), Terminators.end());
    if (NumTerminators < 2)
      continue;

    MachineInstr *T1 = &*Terminators.begin();
    MachineInstr *T2 = &*std::next(Terminators.begin());
  }
#endif

  for (MachineBasicBlock &MBB : MF) {
    // There are three types of terminator groups.
    // 1. A non-zero chain of JCCs optionally followed by a JMP.
    // 2. A RET.
    // 3. An indirect jump.
    // 4. No terminators or a single unconditional jump.

    bool HasJCC = false;
    bool HasRet = false;
    bool HasInd = false;

    for (const MachineInstr &MI : MBB.terminators()) {
      assert(MI.isTerminator());
      if (MI.isConditionalBranch())
        HasJCC = true;
      else if (MI.isReturn())
        HasRet = true;
      else if (MI.isIndirectBranch())
        HasInd = true;
      else
        assert(MI.isUnconditionalBranch());
    }

    if (HasJCC) {
      assert(!HasRet && !HasInd);
      handleConditional(MBB);
    } else if (HasRet) {
      assert(!HasInd);
      handleReturn(MBB);
    } else if (HasInd) {
      handleIndirect(MBB);
    }
  }

#if 0
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : llvm::make_early_inc_range(MBB)) {
      if (!MI.isTerminator())
        continue;
      
    }
  }
#endif

  MF.verify();

  return true;
}

void X86ControlFlowIndirectionPass::handleConditional(MachineBasicBlock &MBB) {
  LLVM_DEBUG(dbgs() << "[condbr -> indbr] before: " << MBB);

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
      
    if (MI.getOpcode() != X86::JCC_1)
      errs() << MI;
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
  BuildMI(MBB, MBBI, Loc, TII->get(X86::JMP64r))
      .addReg(Reg);

  for (auto it = MBBI; it != MBB.end(); ++it) {
    assert(!it->getPreInstrSymbol() && !it->getPostInstrSymbol());
  }
    
  MBB.erase(MBBI, MBB.end());

  LLVM_DEBUG(dbgs() << "[condbr -> indbr] after: " << MBB);
}

void X86ControlFlowIndirectionPass::handleIndirect(MachineBasicBlock &MBB) {}

// NHM-FIXME: We can't do this here anyway.
void X86ControlFlowIndirectionPass::handleReturn(MachineBasicBlock &MBB) {}

INITIALIZE_PASS(X86ControlFlowIndirectionPass, PASS_KEY, "X86 control-flow indirection pass", false, false)
FunctionPass *llvm::createX86ControlFlowIndirectionPass() {
  return new X86ControlFlowIndirectionPass();
}
