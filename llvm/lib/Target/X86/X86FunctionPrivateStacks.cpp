#include "llvm/CodeGen/FunctionPrivateStacks.h" // NHM-TODO: Maybe don't need this?

#include "X86.h"
#include "X86Subtarget.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/CodeGen/MachineFrameInfo.h"

using namespace llvm;

#define PASS_KEY "x86-fps"
#define DEBUG_TYPE PASS_KEY

namespace {


class X86FunctionPrivateStacks : public MachineFunctionPass {
public:
  static char ID;

  X86FunctionPrivateStacks() : MachineFunctionPass(ID) {
    initializeX86FunctionPrivateStacksPass(*PassRegistry::getPassRegistry());
  }

  bool runOnMachineFunction(MachineFunction &MF) override;
};

bool X86FunctionPrivateStacks::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableFunctionPrivateStacks)
    return false;

  const Module& M = *MF.getFunction().getParent();
  
  // For now, simply verify that stack realignment is not required,
  // and that we only need a stack pointer, not a base pointer or frame pointer.
  auto &STI = MF.getSubtarget<X86Subtarget>();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MFI = MF.getFrameInfo();
  if (TRI->hasBasePointer(MF))
    report_fatal_error("No function should have base pointer with FPS enabled!");

  MachineBasicBlock &EntryMBB = MF.front();
  auto EntryMBBI = EntryMBB.begin();

  // BB1: 
  //   MOV rbx, [__fps_stackptr]
  //   CMP rbx, 0
  //   JNZ BB3
  // BB2: 
  //   CALL __fps_alloc
  //   MOV rbx, [__fps_stackptr]
  // BB3:
  //   SUB rbx, <frame-size>
  //   ...

#if 0
  // First, let's try adding a new symbol.
  MCContext& MCC = MF.getContext();
  MCSymbol *StackPtrSym = MCC.getOrCreateSymbol("__fps_stackptr_" + MF.getName());
  MCSection *DataSection = MCC.getObjectFileInfo()->getDataSection();
  auto *Fragment = new MCDataFragment(DataSection);
  Fragment->getContents().resize(8); // 8-byte stack pointer
  StackPtrSym->setFragment(Fragment);
  Fragment->setAtom(StackPtrSym);

  BuildMI(EntryMBB, EntryMBBI, DebugLoc(), TII->get(X86::MOV64rm), X86::RAX)
      .addReg(X86::RIP)
      .addImm(1)
      .addReg(0)
      .addSym(StackPtrSym)
      .addReg(0);
#endif

  auto *StackPtrSym = M.getNamedValue(StringRef(("__fps_stackptr_" + MF.getName()).str()));

  MachineBasicBlock &LoadMBB = *MF.CreateMachineBasicBlock();
  MachineBasicBlock &AllocMBB = *MF.CreateMachineBasicBlock();
  MF.push_front(&AllocMBB);
  MF.push_front(&LoadMBB);
  
  auto LoadMBBI = LoadMBB.begin();
  BuildMI(LoadMBB, LoadMBBI, DebugLoc(), TII->get(X86::MOV64rm), X86::RBX)
      .addReg(X86::RIP)
      .addImm(1)
      .addReg(0)
      .addGlobalAddress(StackPtrSym)
      .addReg(0);
  BuildMI(LoadMBB, LoadMBBI, DebugLoc(), TII->get(X86::CMP64ri8))
      .addReg(X86::RBX)
      .addImm(0);
  TII->insertBranch(LoadMBB, &EntryMBB, &AllocMBB, {MachineOperand::CreateImm(X86::COND_NE)}, DebugLoc());
  LoadMBB.addSuccessor(&AllocMBB);
  LoadMBB.addSuccessor(&EntryMBB);
  for (auto &LI : EntryMBB.liveins())
    LoadMBB.addLiveIn(LI);

  auto AllocMBBI = AllocMBB.begin();
  const uint32_t *RegMask = TRI->getCallPreservedMask(MF, CallingConv::C);
  for (auto &LI : EntryMBB.liveins())
    AllocMBB.addLiveIn(LI);
  
  // Save argument registers to shared stack.
  struct ArgSpillInfo {
    MCRegister Reg;
    const TargetRegisterClass *RC;
    int FI;
  };
  SmallVector<ArgSpillInfo> ArgSpillInfos;
  for (auto &LI : AllocMBB.liveins()) {
    ArgSpillInfo Info;
    Info.Reg = LI.PhysReg;
    Info.RC = TRI->getMinimalPhysRegClass(Info.Reg);
    const auto SpillSize = TRI->getSpillSize(*Info.RC);
    Info.FI = MFI.CreateSpillStackObject(SpillSize, Align(SpillSize));
    TII->storeRegToStackSlot(AllocMBB, AllocMBBI, Info.Reg, true, Info.FI, Info.RC, TRI, X86::NoRegister);
    ArgSpillInfos.push_back(Info);
  }

  BuildMI(AllocMBB, AllocMBBI, DebugLoc(), TII->get(X86::CALL64pcrel32))
      .addExternalSymbol("__fps_alloc")
      .addRegMask(RegMask);
  BuildMI(AllocMBB, AllocMBBI, DebugLoc(), TII->get(X86::MOV64rm), X86::RBX)
      .addReg(X86::RIP)
      .addImm(1)
      .addReg(0)
      .addGlobalAddress(StackPtrSym)
      .addReg(0);

  // Restore argument registers to shared stack.
  for (const ArgSpillInfo &Info : ArgSpillInfos)
    TII->loadRegFromStackSlot(AllocMBB, AllocMBBI, Info.Reg, Info.FI, Info.RC, TRI, X86::NoRegister);
  TII->insertUnconditionalBranch(AllocMBB, &EntryMBB, DebugLoc());
  AllocMBB.addSuccessor(&EntryMBB);

  return true;
}

}

INITIALIZE_PASS(X86FunctionPrivateStacks, PASS_KEY, "X86 Function Private Stacks", false, false)

FunctionPass *llvm::createX86FunctionPrivateStacksPass() {
  return new X86FunctionPrivateStacks();
}

char X86FunctionPrivateStacks::ID = 0;
