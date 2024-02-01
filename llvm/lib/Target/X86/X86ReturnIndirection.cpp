#include "X86.h"
#include "X86InstrInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"

using namespace llvm;

#define PASS_KEY "x86-retind"
#define DEBUG_TYPE PASS_KEY

namespace {

class X86ReturnIndirectionPass final : public MachineFunctionPass {
public:
  X86ReturnIndirectionPass() : MachineFunctionPass(ID) {}
  static char ID;
  StringRef getPassName() const override {
    return "X86 Return Indirection Pass";
  }
  bool runOnMachineFunction(MachineFunction &MF) override;
private:
  const TargetInstrInfo *TII;
};

}

char X86ReturnIndirectionPass::ID = 0;

bool X86ReturnIndirectionPass::runOnMachineFunction(MachineFunction &MF) {
  TII = MF.getSubtarget().getInstrInfo();
  bool Changed = false;
  for (MachineBasicBlock &MBB : MF) {
    if (MBB.terminators().empty())
      continue;
    MachineInstr &Ret = MBB.back();
    if (Ret.isCall() || !Ret.isReturn())
      continue;
    LLVM_DEBUG(dbgs() << "found return: " << Ret);
    assert(Ret.getOpcode() == X86::RET64);
    BuildMI(MBB, Ret.getIterator(), DebugLoc(), TII->get(X86::ADD64ri8), X86::RSP)
        .addReg(X86::RSP)
        .addImm(8);
    BuildMI(MBB, Ret.getIterator(), DebugLoc(), TII->get(X86::JMP64m))
        .addReg(X86::RSP)
        .addImm(1)
        .addReg(X86::NoRegister)
        .addImm(-8)
        .addReg(X86::NoRegister);
    Ret.eraseFromParent();
    Changed = true;
  }
  return Changed;
}

INITIALIZE_PASS(X86ReturnIndirectionPass, PASS_KEY, "X86 return indirection pass", false, false)
FunctionPass *llvm::createX86ReturnIndirectionPass() {
  return new X86ReturnIndirectionPass();
}
