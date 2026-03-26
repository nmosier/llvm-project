#include "llvm/CodeGen/FunctionPrivateStacks.h" // NHM-TODO: Maybe don't need this?

#include "AArch64.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/IR/Function.h"

using namespace llvm;

#define PASS_KEY "aarch64-fps"
#define DEBUG_TYPE PASS_KEY

namespace {

class AArch64FunctionPrivateStacks : public MachineFunctionPass {
public:
  static char ID;

  AArch64FunctionPrivateStacks() : MachineFunctionPass(ID) {
    initializeAArch64FunctionPrivateStacksPass(*PassRegistry::getPassRegistry());
  }

  bool runOnMachineFunction(MachineFunction &MF) override;
};

} // namespace

bool AArch64FunctionPrivateStacks::runOnMachineFunction(MachineFunction &MF) {
  if (!MF.getFunction().hasFnAttribute(Attribute::FunctionPrivateStack))
    return false;
  assert(!MF.getName().starts_with("__fps_"));

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