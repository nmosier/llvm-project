#include "X86.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "X86InstrInfo.h"

using namespace llvm;

#define PASS_KEY "x86-lfence"
#define DEBUG_TYPE PASS_KEY

namespace {

class X86NaiveLfencePass final : public MachineFunctionPass {
public:
  X86NaiveLfencePass() : MachineFunctionPass(ID) {}
  StringRef getPassName() const override {
    return "X86 Naive LFENCE Pass";
  }
  bool runOnMachineFunction(MachineFunction &MF) override;
  static char ID;
private:
  const TargetInstrInfo *TII;
};

}

char X86NaiveLfencePass::ID = 0;

bool X86NaiveLfencePass::runOnMachineFunction(MachineFunction &MF) {
  TII = MF.getSubtarget().getInstrInfo();
  
  LLVM_DEBUG(dbgs() << "***** " << getPassName() << " : " << MF.getName() << " *****\n");

  // In this pass, we insert an LFENCE following every conditional branch, load, and ... wait a minute, we can ... no we can't.
  // Insert an LFENCE following at each of the following:
  //  - conditional branch (after)
  //  - ENDBRANCH instruction (after)
  //  - callsite (after)
  //  - load (after)

  bool Changed = false;

  auto InsertLFENCE = [&] (MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI) {
    while (MBBI != MBB.end() && MBBI->getOpcode() == X86::ENDBR64)
      ++MBBI;
    if ((MBBI != MBB.end() && MBBI->getOpcode() == X86::LFENCE) ||
        (MBBI != MBB.begin() && std::prev(MBBI)->getOpcode() == X86::LFENCE))
      return;
    BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::LFENCE));
    Changed = true;
  };

  for (MachineBasicBlock &MBB : MF) {
    // Handle conditional branches.
    if (llvm::any_of(MBB.terminators(), [] (const MachineInstr &MI) -> bool {
      return MI.isConditionalBranch();
    })) {
      for (MachineBasicBlock *Succ : MBB.successors()) {
        InsertLFENCE(*Succ, Succ->begin());
      }
    }

    for (MachineInstr &MI : llvm::make_early_inc_range(MBB)) {
      // Handle ENDBRANCH instructions.
      if (MI.getOpcode() == X86::ENDBR64)
        InsertLFENCE(MBB, std::next(MI.getIterator()));

      // Handle callsite instructions.
      if (MI.isCall() && !MI.isTerminator())
        InsertLFENCE(MBB, std::next(MI.getIterator()));
      // NHM-FIXME: should LFENCe anfter anywya.

      // Handle loads.
      if (MI.mayLoad())
        InsertLFENCE(MBB, std::next(MI.getIterator()));
    }
  }

  return Changed;
}


INITIALIZE_PASS(X86NaiveLfencePass, PASS_KEY, "X86 naive lfence", false, false)
FunctionPass *llvm::createX86NaiveLfencePass() {
  return new X86NaiveLfencePass();
}
