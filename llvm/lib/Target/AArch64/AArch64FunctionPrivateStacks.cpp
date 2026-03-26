#include "llvm/CodeGen/FunctionPrivateStacks.h" // NHM-TODO: Maybe don't need this?

#include "AArch64.h"
#include "AArch64Subtarget.h"
#include "AArch64InstrInfo.h"
#include "AArch64RegisterInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/IR/Function.h"
#include "llvm/CodeGen/MachineFrameInfo.h"

using namespace llvm;

#define PASS_KEY "aarch64-fps"
#define DEBUG_TYPE PASS_KEY

static constexpr MCPhysReg PSPReg = AArch64::X15;

namespace {

class AArch64FunctionPrivateStacks : public MachineFunctionPass {
public:
  static char ID;

  AArch64FunctionPrivateStacks() : MachineFunctionPass(ID) {
    initializeAArch64FunctionPrivateStacksPass(*PassRegistry::getPassRegistry());
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

private:
  const AArch64InstrInfo *TII;
  const AArch64RegisterInfo *TRI;
  MachineFrameInfo *MFI;
};

} // namespace

bool AArch64FunctionPrivateStacks::runOnMachineFunction(MachineFunction &MF) {
  if (!MF.getFunction().hasFnAttribute(Attribute::FunctionPrivateStack))
    return false;
  assert(!MF.getName().starts_with("__fps_"));

  auto &STI = MF.getSubtarget<AArch64Subtarget>();
  TII = STI.getInstrInfo();
  TRI = STI.getRegisterInfo();
  MFI = &MF.getFrameInfo();

  // NHM-FIXME: Remove this debug check.
  for (const MachineBasicBlock &MBB : MF)
    for (const MachineInstr &MI : MBB)
      for (const MachineOperand &MO : MI.operands())
        if (MO.isReg())
          assert(MO.getReg() != PSPReg);

  // Make sure there is no base pointer and no dynamic stack allocations.
  if (EnableFPSStrictMode) {
    assert(!TRI->hasBasePointer(MF) &&
           "No function should have a base pointer!");
    assert(!MFI->hasVarSizedObjects() && "All variable-sized stack objects should have been moved to the unsafe stack already!");
  }

  errs() << "HERE\n";

  // NHM-FIXME: Implement the rest.
  return true;
}

INITIALIZE_PASS(AArch64FunctionPrivateStacks, PASS_KEY,
                "AArch64 Function Private Stacks", false, false)

FunctionPass *llvm::createAArch64FunctionPrivateStacksPass() {
  return new AArch64FunctionPrivateStacks();
}

char AArch64FunctionPrivateStacks::ID = 0;