#include "llvm/CodeGen/FunctionPrivateStacks.h" // NHM-TODO: Maybe don't need this?

#include "X86.h"
#include "X86Subtarget.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "MCTargetDesc/X86BaseInfo.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/Target/TargetMachine.h"

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

private:
  const TargetMachine *TM;
  const TargetInstrInfo *TII;
  const GlobalValue *ThreadLocalStackVecSym;

  bool needsFarTLS() const {
    return TM->getCodeModel() == CodeModel::Medium || TM->getCodeModel() == CodeModel::Large;
  }

  void loadPrivateStackPointer(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, const DebugLoc &Loc = DebugLoc());
  void loadPrivateStackBase(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, const DebugLoc &Loc = DebugLoc());
  void loadPrivateStackPointerAndBase(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, const DebugLoc &Loc = DebugLoc());
  void storePrivateStackPointer(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, const DebugLoc &Loc = DebugLoc());

  bool frameIndexOnlyUsedInMemoryOperands(int FI, MachineFunction &MF, SmallVectorImpl<MachineOperand *> &Uses);
};

bool X86FunctionPrivateStacks::frameIndexOnlyUsedInMemoryOperands(int FI, MachineFunction &MF, SmallVectorImpl<MachineOperand *> &Uses) {
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      for (MachineOperand &MO : MI.operands()) {
        if (!(MO.isFI() && MO.getIndex() == FI))
          continue;
        const MCInstrDesc &Desc = MI.getDesc();
        int MemRefBeginIdx = X86II::getMemoryOperandNo(Desc.TSFlags);
        if (MemRefBeginIdx < 0)
          return false;
        MemRefBeginIdx += X86II::getOperandBias(Desc);
        if (MO.getOperandNo() != static_cast<unsigned>(MemRefBeginIdx))
          return false;
        if (needsFarTLS()) {
          const MachineOperand &IndexOp = MI.getOperand(MemRefBeginIdx + 2); // NHM-FIXME: Symbolize.
          if (!(IndexOp.isReg() && IndexOp.getReg() == X86::NoRegister))
            return false;
        }
        const MachineOperand &SegOp = MI.getOperand(MemRefBeginIdx + X86::AddrSegmentReg);
        if (!(SegOp.isReg() && SegOp.getReg() == X86::NoRegister))
          return false;
        Uses.push_back(&MO);
      }
    }
  }
  return true;
}

#if 0
void X86FunctionPrivateStacks::loadPrivateStackPointerAndBase(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, const DebugLoc& Loc) {
  loadPrivateStackPointer(MBB, MBBI, Loc);
  loadPrivateStackBase(MBB, MBBI, Loc);
}
#endif

void X86FunctionPrivateStacks::loadPrivateStackPointer(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, const DebugLoc &Loc) {
  // For now, assume local dynamic.
  // TO_DTPOFF
#if 0
  BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64ri32), X86::RBX)
      .addGlobalAddress(ThreadLocalStackVecSym, 0, X86II::MO_DTPOFF);
  BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), X86::RBX)
      .addReg(X86::RBX)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(0)
      .addReg(X86::FS);
#else
  BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), X86::RBX)
      .addReg(X86::NoRegister)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addGlobalAddress(ThreadLocalStackVecSym, 0, X86II::MO_DTPOFF)
      .addReg(X86::FS);
#endif

#if 0
  // NHM-FIXME: add MachineMemOperand.
  if (needsFarTLS()) {
    // MOVABS rbx, __fps_stackptr
    // MOV rbx, fs[rbx]
    BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64ri), X86::RBX)
        .addGlobalAddress(StackPtrSym, 0, X86II::MO_TPOFF);
    BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), X86::RBX)
        .addReg(X86::RBX)
        .addImm(1)
        .addReg(X86::NoRegister)
        .addImm(0)
        .addReg(X86::FS);
    BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64ri), X86::R15)
        .addGlobalAddress(StackPtrSym, 0, X86II::MO_TPOFF);
    // NHM-FIXME: MEmory operand.
  } else {
    // MOV rbx, fs[__fps_stackptr]
    BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), X86::RBX)
        .addReg(X86::NoRegister)
        .addImm(1)
        .addReg(X86::NoRegister)
        .addGlobalAddress(StackPtrSym, 0, X86II::MO_TPOFF)
        .addReg(X86::FS);
  }
#endif
}

#if 0
void X86FunctionPrivateStacks::loadPrivateStackBase(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, const DebugLoc &Loc) {
  if (needsFarTLS()) {
    // MOVABS r15, __fps_stack
    BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64ri), X86::R15)
        .addGlobalAddress(StackBaseSym, 0, X86II::MO_TPOFF);
  }
}
#endif

#if 0
void X86FunctionPrivateStacks::storePrivateStackPointer(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, const DebugLoc &Loc) {
  // NHM-FIXME: Add machinememoperand.
  if (needsFarTLS()) {
    // MOVABS r15, __fps_stackptr
    // MOV fs:[r15], rbx
    BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64ri), X86::R15)
        .addGlobalAddress(StackPtrSym, 0, X86II::MO_TPOFF);
    BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64mr))
        .addReg(X86::R15)
        .addImm(1)
        .addReg(X86::NoRegister)
        .addImm(0)
        .addReg(X86::FS)
        .addReg(X86::RBX);
  } else {
    // MOV fs:[__fps_stackptr], rbx
    BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64mr))
        .addReg(X86::NoRegister)
        .addImm(1)
        .addReg(X86::NoRegister)
        .addGlobalAddress(StackPtrSym, 0, X86II::MO_TPOFF)
        .addReg(X86::FS)
        .addReg(X86::RBX);
  }
}
#endif
  
bool X86FunctionPrivateStacks::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableFunctionPrivateStacks)
    return false;

  TM = &MF.getTarget();

  const Module& M = *MF.getFunction().getParent();
  
  // For now, simply verify that stack realignment is not required,
  // and that we only need a stack pointer, not a base pointer or frame pointer.
  auto &STI = MF.getSubtarget<X86Subtarget>();
  TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MFI = MF.getFrameInfo();
  auto &MRI = MF.getRegInfo();

  // NHM-FIXME: Make it an assert?
  if (TRI->hasBasePointer(MF))
    report_fatal_error("No function should have base pointer with FPS enabled!");
  assert(MRI.reg_empty(X86::RBX) && "Expected no existing uses of RBX for functions requiring a private stack!");
  assert(!MFI.hasVarSizedObjects() && "All variable-sized stack objects should have been moved to the unsafe stack already!");


  ThreadLocalStackVecSym = M.getNamedValue("__fps_thdstacks");
  // NHM-FIXME: Assertions.

  DebugLoc Loc;

  uint64_t PrivateFrameSize = 0;
#if 0
  DenseMap<int, uint64_t> ObjIdxToOff;
  for (int FI = MFI.getObjectIndexBegin(); FI < MFI.getObjectIndexEnd(); ++FI) {
    if (MFI.isFixedObjectIndex(FI))
      continue;
    SmallVector<MachineOperand *> Uses;
    if (!frameIndexOnlyUsedInMemoryOperands(FI, MF, Uses)) {
      LLVM_DEBUG(dbgs() << "skipping frame index " << FI << " which has a non-memory-operand use\n");
      continue;
    }

    const auto PrivateFrameOffset = PrivateFrameSize;
    PrivateFrameSize += MFI.getObjectSize(FI);

    // Move uses to safe stack.
    for (MachineOperand *UseOp : Uses) {
      // Orig:
      //   LEA r1, [FrameIndex + scale*r2 + disp]
      // Rewritten (small code):
      //   LEA r1, [rbx + scale*r2 + disp+PrivateFrameOffset+TLSOffset]
      //   ADD r1, fs:[0] # NOTE: this only works if EFLAGS is not live. 
      // Rewritten (large code):
      //   LEA r1, [rbx + scale*r2 + disp+PrivateFrameOffset]
      //   ADD r1, fs:[0]
      //   ADD r1, TLSOffset
      
      MachineInstr *MI = UseOp->getParent();
      const unsigned MemRefIdxBegin = UseOp->getOperandNo() - X86::AddrBaseReg;
      MachineOperand &BaseOp = MI->getOperand(MemRefIdxBegin + X86::AddrBaseReg);
      MachineOperand &ScaleOp = MI->getOperand(MemRefIdxBegin + X86::AddrScaleAmt);
      MachineOperand &IndexOp = MI->getOperand(MemRefIdxBegin + X86::AddrIndexReg);
      MachineOperand &DispOp = MI->getOperand(MemRefIdxBegin + X86::AddrDisp);
      MachineOperand &SegmentOp = MI->getOperand(MemRefIdxBegin + X86::AddrSegmentReg);

      if (needsFarTLS()) {
        report_fatal_error("large code not supported yet");
      } else {
        BaseOp.ChangeToRegister(X86::RBX, /*isDef*/false);
        DispOp.ChangeToGA(StackBaseSym, DispOp.getImm() + PrivateFrameOffset, X86II::MO_TPOFF);

        switch (MI->getOpcode()) {
        case X86::LEA64r:
          BuildMI(*MI->getParent(), std::next(MI->getIterator()), Loc, TII->get(X86::ADD64rm), MI->getOperand(0).getReg())
              .addReg(X86::NoRegister)
              .addImm(1)
              .addReg(X86::NoRegister)
              .addImm(0)
              .addReg(X86::FS);
          break;

        case X86::LEA32r:
        case X86::LEA16r:
          report_fatal_error("Unexpected 16- or 32-bit LEA with frame index operand");

        default:
          SegmentOp.setReg(X86::FS);
          break;
        }
      }
      
    }
    
  }
#endif




  MachineBasicBlock &EntryMBB = MF.front();
  MachineBasicBlock::iterator EntryMBBI = EntryMBB.begin();

  loadPrivateStackPointer(EntryMBB, EntryMBBI);
  


#if 0
  MachineBasicBlock &EntryMBB = MF.front();
  MachineBasicBlock &AllocMBB = *MF.CreateMachineBasicBlock();
  MF.push_front(&AllocMBB);
  MachineBasicBlock &OverflowMBB = *MF.CreateMachineBasicBlock();
  MF.push_back(&OverflowMBB);

  // NHM-FIXME: Detect 'norecurse' functions.
  // Functions with 'norecurse' attribute: access directly via thread-local variable.
  // Otherwise, the following:
  // .fps.alloc:
  //   
  
  // .fps.alloc:
  //   MOV rbx, [__fps_stackptr]
  //   SUB rbx, <frame-size>
  //   JB rbx, .fps.stackoverflow
  //  .fps.clamp:
  //   CMOVB rbx, [__fps_stackptr]
  //   ...
  
  // .fps.stackoverflow:
  //   CALL abort
  //   LFENCE

  const auto AllocMBBI = AllocMBB.begin();
  loadPrivateStackPointer(AllocMBB, AllocMBB.begin());

  // NHM-FIXME: Use 8-bit vs. 32-bit depending on operand size.
  if (needsFarTLS()) {
    BuildMI(AllocMBB, AllocMBBI, Loc, TII->get(X86::COPY), X86::R15)
        .addReg(X86::RBX);
  }
  BuildMI(AllocMBB, AllocMBBI, Loc, TII->get(X86::SUB64ri32), X86::RBX)
      .addReg(X86::RBX)
      .addImm(PrivateFrameSize);
  TII->insertBranch(AllocMBB, &OverflowMBB, &EntryMBB, {MachineOperand::CreateImm(X86::COND_B)}, Loc);
  AllocMBB.addSuccessor(&OverflowMBB);
  AllocMBB.addSuccessor(&EntryMBB);
  for (auto &LI : EntryMBB.liveins())
    AllocMBB.addLiveIn(LI);

  BuildMI(OverflowMBB, OverflowMBB.end(), Loc, TII->get(X86::TRAP)); // NHM-FIXME: Confirm this is what they do too.

  auto EntryMBBI = EntryMBB.begin();
  EntryMBB.addLiveIn(X86::EFLAGS);
  EntryMBB.addLiveIn(X86::RBX);
  if (needsFarTLS()) {
    BuildMI(EntryMBB, EntryMBBI, Loc, TII->get(X86::CMOV64rr), X86::RBX)
        .addReg(X86::RBX)
        .addReg(X86::R15)
        .addImm(X86::COND_B);
    EntryMBB.addLiveIn(X86::R15);
  } else {
    BuildMI(EntryMBB, EntryMBBI, Loc, TII->get(X86::CMOV64rm), X86::RBX)
                             .addReg(X86::RBX)
                             .addReg(X86::NoRegister)
                             .addImm(1)
                             .addReg(X86::NoRegister)
                             .addGlobalAddress(StackPtrSym, 0, X86II::MO_TPOFF)
                             .addReg(X86::FS)
                             .addImm(X86::COND_B);
  }
  loadPrivateStackBase(EntryMBB, EntryMBBI);
  storePrivateStackPointer(EntryMBB, EntryMBBI);

  SmallVector<MachineInstr *> Returns, Calls;
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      if (MI.isReturn()) {
        Returns.push_back(&MI);
      } else if (MI.isCall()) {
        Calls.push_back(&MI);
      }
    }
  }

  for (MachineInstr *Ret : Returns) {
    MachineBasicBlock &EpilogMBB = *Ret->getParent();
    MachineBasicBlock &RetMBB = *MF.CreateMachineBasicBlock();
    MF.insert(std::next(EpilogMBB.getIterator()), &RetMBB);

    LivePhysRegs LPR(*TRI);
    LPR.addLiveIns(EpilogMBB);
    for (auto MBBI = Ret->getParent()->begin(); MBBI != Ret->getIterator(); ++MBBI) {
      SmallVector<std::pair<MCPhysReg, const MachineOperand *>> Clobbers;
      LPR.stepForward(*MBBI, Clobbers);
    }
    RetMBB.splice(RetMBB.end(), &EpilogMBB, Ret->getIterator());
    RetMBB.transferSuccessors(&EpilogMBB);
    for (MCPhysReg LiveReg : LPR) {
      RetMBB.addLiveIn(LiveReg);
    }
    storePrivateStackPointer(RetMBB, RetMBB.begin());
    
    // ADD rbx, <frame-size>
    // CMP rbx, <stack-size>
    // JAE rbx, .fps.stackoverflow
    // NHM-FIXME: Fix debug loc.
    BuildMI(EpilogMBB, EpilogMBB.end(), Loc, TII->get(X86::ADD64ri32), X86::RBX)
        .addReg(X86::RBX)
        .addImm(PrivateFrameSize);
    // NHM-FIXME: Use ri8 vs. ri32 whereever appropriate.
    BuildMI(EpilogMBB, EpilogMBB.end(), Loc, TII->get(X86::CMP64ri32))
        .addReg(X86::RBX)
        .addImm(PrivateStackSize);
    TII->insertBranch(EpilogMBB, &OverflowMBB, &RetMBB, {MachineOperand::CreateImm(X86::COND_A)}, Loc);
    EpilogMBB.addSuccessor(&RetMBB);
    EpilogMBB.addSuccessor(&OverflowMBB);

    // NHM-FIXME: Update live registers?

    // NHM-FIXME: Add machine mem operands.
  }

  // Reload after calls.
  for (MachineInstr *Call : Calls)
    loadPrivateStackPointerAndBase(*Call->getParent(), std::next(Call->getIterator()));

  // Reload after instructions that clobber it.
  // NHM-FIXME: Don't double-reload after CALLs.
  SmallVector<MachineInstr *> Clobbers;
  for (MachineBasicBlock &MBB : MF)
    for (MachineInstr &MI : MBB)
      for (const MachineOperand &MO : MI.operands())
        if (MO.isRegMask() && (MO.clobbersPhysReg(X86::RBX) || (needsFarTLS() && MO.clobbersPhysReg(X86::R15))))
          Clobbers.push_back(&MI);
  for (MachineInstr *Clobber : Clobbers)
    if (Clobber->isTerminator())
      for (MachineBasicBlock *Succ : Clobber->getParent()->successors())
        loadPrivateStackPointerAndBase(*Succ, Succ->begin());
    else
      loadPrivateStackPointerAndBase(*Clobber->getParent(), std::next(Clobber->getIterator()));
#endif

#if 0
  // Reload at the target of EH_SjLj_Setup instructions.
  SmallVector<MachineInstr *> EH_SjLj_Setups;
  for (MachineBasicBlock &MBB : MF)
    for (MachineInstr &MI : MBB)
      if (MI.getOpcode() == X86::EH_SjLj_Setup)
        EH_SjLj_Setups.push_back(&MI);
  for (MachineInstr *MI : EH_SjLj_Setups) {
    MachineBasicBlock &TgtMBB = *MI->getOperand(0).getMBB();
    loadPrivateStackPointerAndBase(TgtMBB, TgtMBB.begin());
  }
#endif

  MF.verify();
#if 0 
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      if (MI.getOpcode() == X86::CMOV32rm) {
        errs() << "TRACE: "; MI.dump();
        exit(1);
      }
    }
  }
#endif


  // NHM-FIXME: Check if it tracks liveness.

  //   CMP rbx, &__fps_stackend
  //   
  //   MOV [__fps_stackptr], rbx
  

  // .fps.1:, 
  //   MOV rbx, [__fps_stackptr]
  //   SUB rbx, <frame-size>
  //   MOV rbx, [__
  

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

#if 0
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
#endif

  return true;
}

}

INITIALIZE_PASS(X86FunctionPrivateStacks, PASS_KEY, "X86 Function Private Stacks", false, false)

FunctionPass *llvm::createX86FunctionPrivateStacksPass() {
  return new X86FunctionPrivateStacks();
}

char X86FunctionPrivateStacks::ID = 0;
