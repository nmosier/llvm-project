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
#include "llvm/CodeGen/RegisterScavenging.h"
#include "llvm/CodeGen/RegAllocPBQP.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"

using namespace llvm;

#define PASS_KEY "x86-fps"
#define DEBUG_TYPE PASS_KEY

namespace {

// NHM-FIXME: This must be implemented somewhere.
// NHM-FIXME: use llvm::alignTo
template <typename T>
T align_up(T value, T align) {
  return ((value + align - 1) / align) * align;
}

class X86FunctionPrivateStacks : public MachineFunctionPass {
public:
  static char ID;

  FunctionPass *RegAllocPass;

  X86FunctionPrivateStacks() : MachineFunctionPass(ID) {
    initializeX86FunctionPrivateStacksPass(*PassRegistry::getPassRegistry());
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

private:
  const TargetMachine *TM;
  const TargetInstrInfo *TII;
  const X86RegisterInfo *TRI;
  MachineFrameInfo *MFI;
  const GlobalValue *StackIdxSym;
  const GlobalValue *ThdStackPtrsSym;

  void getPointerToFPSData(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, const DebugLoc &Loc, const GlobalValue *Member, Register Reg);

  // NOTE: Permits PtrReg == ValReg.
  void loadPrivateStackPointer(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Reg, const DebugLoc &Loc = DebugLoc());

  // NOTE: Does not permit PtrReg == ValReg.
  void storePrivateStackPointer(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Reg, const DebugLoc &Loc = DebugLoc());

  bool frameIndexOnlyUsedInMemoryOperands(int FI, MachineFunction &MF, SmallVectorImpl<MachineOperand *> &Uses);
  void instrumentSetjmps(MachineFunction &MF);

  void partialRedundancyElimination(MachineFunction &MF, ArrayRef<MachineInstr *> Uses, ArrayRef<MachineInstr *> Kills, SmallVectorImpl<std::pair<MachineBasicBlock *, MachineBasicBlock::iterator>> &InsertPts);

  void assignRegsForPrivateStackPointer(MachineFunction &MF, ArrayRef<MachineInstr *> Uses, const DenseMap<int, uint64_t>& PrivateFrameInfo);
  void emitPrologue(MachineFunction &MF, unsigned PrivateFrameSize);
  void emitEpilogue(MachineFunction &MF, unsigned PrivateFrameSize);
};

static MCPhysReg getFreeReg(const LivePhysRegs &LPR, const MachineRegisterInfo &MRI, ArrayRef<MCPhysReg> IgnoreRegs = {}) {
  for (MCPhysReg Reg : X86::GR64RegClass)
    if (LPR.available(MRI, Reg) && !is_contained(IgnoreRegs, Reg))
      return Reg;
  return X86::NoRegister;
}

static bool getFreeRegs(const LivePhysRegs &LPR, const MachineRegisterInfo &MRI, unsigned NumFreeRegs, SmallVectorImpl<MCPhysReg> &FreeRegs) {
  for (MCPhysReg Reg : X86::GR64RegClass) {
    if (LPR.available(MRI, Reg)) {
      FreeRegs.push_back(Reg);
      if (FreeRegs.size() == NumFreeRegs)
        return true;
    }
  }
  assert(FreeRegs.size() < NumFreeRegs);
  return false;
}

static MCPhysReg getSpillableReg(const LivePhysRegs &LPR, const TargetRegisterInfo *TRI, const MachineRegisterInfo &MRI) {
    auto it = find_if(X86::GR64RegClass, [&] (MCPhysReg Reg) -> bool {
      if (LPR.contains(Reg))
        return true;
      if (MRI.isReserved(Reg))
        return false;
      for (MCRegAliasIterator R(Reg, TRI, false); R.isValid(); ++R)
        if (LPR.contains(*R))
          return true;
      return false;
    });
    if (it == std::end(X86::GR64RegClass))
      return X86::NoRegister;
    else
      return *it;
  };


void X86FunctionPrivateStacks::emitPrologue(MachineFunction &MF, unsigned PrivateFrameSize) {
  if (PrivateFrameSize == 0)
    return;
  
  MachineBasicBlock &MBB = MF.front();
  auto MBBI = MBB.begin();
  const auto &MRI = MF.getRegInfo();

  SmallVector<MCPhysReg, 2> Regs;
  LivePhysRegs LPR(*TRI);
  LPR.addLiveIns(MBB);
  if (!getFreeRegs(LPR, MRI, 2, Regs))
    report_fatal_error("Failed to get free registers for FPS prologue!");
  assert(Regs.size() == 2);
  assert(!LPR.contains(X86::EFLAGS));

  getPointerToFPSData(MBB, MBBI, DebugLoc(), ThdStackPtrsSym, Regs[0]);
  BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::MOV64rm), Regs[1])
      .addReg(Regs[0])
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(0)
      .addReg(X86::NoRegister);
  BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::SUB64ri32), Regs[1])
      .addReg(Regs[1])
      .addImm(PrivateFrameSize);
  BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::MOV64mr))
      .addReg(Regs[0])
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(0)
      .addReg(X86::NoRegister)
      .addReg(Regs[1]);
}

void X86FunctionPrivateStacks::emitEpilogue(MachineFunction &MF, unsigned PrivateFrameSize) {
  if (PrivateFrameSize == 0)
    return;

  for (MachineBasicBlock &MBB : MF) {
    if (MBB.empty() || !MBB.back().isReturn())
      continue;

    auto MBBI = MBB.back().getIterator();
    const auto &MRI = MF.getRegInfo();

    SmallVector<MCPhysReg, 2> Regs;
    LivePhysRegs LPR(*TRI);
    LPR.addLiveOuts(MBB);
    LPR.stepBackward(MBB.back());
    if (!getFreeRegs(LPR, MRI, 2, Regs))
      report_fatal_error("Failed to get free registers for FPS epilogue!");
    assert(Regs.size() == 2);
    assert(!LPR.contains(X86::EFLAGS));

    getPointerToFPSData(MBB, MBBI, DebugLoc(), ThdStackPtrsSym, Regs[0]);
    BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::MOV64rm), Regs[1])
        .addReg(Regs[0])
        .addImm(1)
        .addReg(X86::NoRegister)
        .addImm(0)
        .addReg(X86::NoRegister);
    BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::ADD64ri32), Regs[1])
        .addReg(Regs[1])
        .addImm(PrivateFrameSize);
    BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::MOV64mr))
        .addReg(Regs[0])
        .addImm(1)
        .addReg(X86::NoRegister)
        .addImm(0)
        .addReg(X86::NoRegister)
        .addReg(Regs[1]);
  }
}

void X86FunctionPrivateStacks::assignRegsForPrivateStackPointer(MachineFunction &MF, ArrayRef<MachineInstr *> Uses, const DenseMap<int, uint64_t> &PrivateFrameInfo) {
  const auto &MRI = MF.getRegInfo();
  auto &MFI = MF.getFrameInfo();

  // For now, just try running Register Scavenger on all windows.
  for (MachineBasicBlock &MBB : MF) {
    int ScavengedFI = MFI.CreateSpillStackObject(8, Align(8));
    
    // Find all use-use ranges.
    SmallVector<MachineInstr *> Nodes; // Uses or kills.
    auto isUse = [&] (MachineInstr *MI) {
      return is_contained(Uses, MI);
    };
    auto isKill = [&] (MachineInstr *MI) {
      return MI->isCall();
    };
    for (MachineInstr &MI : MBB)
      if (isUse(&MI) || isKill(&MI))
        Nodes.push_back(&MI);


    auto it1 = Nodes.begin();
    while (true) {
      it1 = std::find_if(it1, Nodes.end(), isUse);
      if (it1 == Nodes.end())
        break;

      // Find last use.
      MCPhysReg PSPReg = X86::NoRegister;
      auto it2 = std::find_if(std::next(it1), Nodes.end(), isKill);
      --it2;
      MachineBasicBlock::iterator PreScavengeIt, PostScavengeIt, FirstUseIt;
      while (true) {
        // Try to use reg scavenger.
        RegScavenger RS;
        RS.addScavengingFrameIndex(ScavengedFI);
        RS.enterBasicBlockEnd(MBB);
        PreScavengeIt = (**it2).getIterator();
        PostScavengeIt = std::next(PreScavengeIt);
        RS.backward(PostScavengeIt);
        PSPReg = RS.scavengeRegisterBackwards(X86::GR64RegClass, (**it1).getIterator(), /*RestoreAfter*/false, /*SPAdj*/0, /*AllowSpill*/true, /*EliminateFrameIndex*/false);
        if (PSPReg != X86::NoRegister) {
          FirstUseIt = (**it1).getIterator();
          it1 = it2;
          break;
        }

        if (it1 == it2)
          report_fatal_error("Failed to scavenge register around a single instruction");

        --it2;
        assert(isUse(*it2));
      }

      assert(PSPReg != X86::NoRegister);

      // Zero out emergency stack slot, if necessary.
      if (std::next(PreScavengeIt) != PostScavengeIt) {
        BuildMI(MBB, PostScavengeIt, DebugLoc(), TII->get(X86::MOV64mi32))
            .addFrameIndex(ScavengedFI)
            .addImm(1)
            .addReg(X86::NoRegister)
            .addImm(0)
            .addReg(X86::NoRegister)
            .addImm(0);
        BuildMI(MBB, PostScavengeIt, DebugLoc(), TII->get(X86::LFENCE));
      }

      // Load private stack pointer.
      LivePhysRegs LPR(*TRI);
      LPR.addLiveOuts(MBB);
      for (MachineInstr &MI : reverse(MBB)) {
        LPR.stepBackward(MI);
        if (MI.getIterator() == FirstUseIt)
          break;
      }
      assert(LPR.available(MRI, PSPReg));
      const bool LiveEFLAGS = LPR.contains(X86::EFLAGS);

      if (LiveEFLAGS) {
        MCPhysReg ScratchReg = getFreeReg(LPR, MRI, /*IgnoreRegs*/{PSPReg});
        bool Spill = (ScratchReg == X86::NoRegister);
        int SpillFI = -1;
        auto MBBI = FirstUseIt;
        if (Spill) {
          // Evict a spillable register.
          for (const MachineOperand &MO : FirstUseIt->operands())
            if (MO.isReg() && MO.isUse() && MO.getReg())
              LPR.removeReg(MO.getReg());
          ScratchReg = getSpillableReg(LPR, TRI, MRI);
          if (!ScratchReg)
            report_fatal_error("Failed to get spillable register for live EFLAGS!");

          SpillFI = MFI.CreateSpillStackObject(8, Align(8));

          // Insert spill to stack.
          TII->storeRegToStackSlot(MBB, MBBI, ScratchReg, /*isKill*/true, SpillFI, &X86::GR64RegClass, TRI, X86::NoRegister);
        }

        // Emit PSP reload code.
        BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::MOV64rm), ScratchReg)
            .addReg(X86::RIP)
            .addImm(1)
            .addReg(X86::NoRegister)
            .addGlobalAddress(StackIdxSym)
            .addReg(X86::NoRegister);
        BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::MOV64rm), PSPReg)
            .addReg(X86::NoRegister)
            .addImm(1)
            .addReg(X86::NoRegister)
            .addGlobalAddress(ThdStackPtrsSym, 0, X86II::MO_DTPOFF)
            .addReg(X86::FS);
        BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::MOV64rm), PSPReg)
            .addReg(ScratchReg)
            .addImm(1)
            .addReg(PSPReg)
            .addImm(0)
            .addReg(X86::NoRegister);

        if (Spill) {
          // Restore scratch register.
          TII->loadRegFromStackSlot(MBB, MBBI, ScratchReg, SpillFI, &X86::GR64RegClass, TRI, X86::NoRegister);
          BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::MOV64mi32))
              .addFrameIndex(SpillFI)
              .addImm(1)
              .addReg(X86::NoRegister)
              .addImm(0)
              .addReg(X86::NoRegister)
              .addImm(0);
          BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::LFENCE));
        }
        
      } else {
        loadPrivateStackPointer(MBB, FirstUseIt, PSPReg);
      }

      // Fixup uses with PSP reg.
      for (auto MBBI = FirstUseIt; MBBI != PostScavengeIt; ++MBBI) {
        if (isUse(&*MBBI)) {
          const int MemRefIdx = X86::getFirstAddrOperandIdx(*MBBI);
          assert(MemRefIdx >= 0);
          MachineOperand &BaseMO = MBBI->getOperand(MemRefIdx + X86::AddrBaseReg);
          MachineOperand &DispMO = MBBI->getOperand(MemRefIdx + X86::AddrDisp);
          assert(BaseMO.isFI());
          assert(DispMO.isImm());
          int FI = BaseMO.getIndex();
          BaseMO.ChangeToRegister(PSPReg, /*isDef*/false); // NHM-FIXME: Update isKill
          assert(PrivateFrameInfo.contains(FI));
          DispMO.setImm(DispMO.getImm() + PrivateFrameInfo.lookup(FI));
        }
      }

      ++it1;
    }
    
  }
}

void X86FunctionPrivateStacks::loadPrivateStackPointer(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Reg, const DebugLoc &Loc) {
  getPointerToFPSData(MBB, MBBI, Loc, ThdStackPtrsSym, Reg);
  BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), Reg)
      .addReg(Reg)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(0)
      .addReg(X86::NoRegister);
}


bool X86FunctionPrivateStacks::frameIndexOnlyUsedInMemoryOperands(int FI, MachineFunction &MF, SmallVectorImpl<MachineOperand *> &Uses) {
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      for (MachineOperand &MO : MI.operands()) {
        if (!(MO.isFI() && MO.getIndex() == FI))
          continue;
        const int MemRefBeginIdx = X86::getFirstAddrOperandIdx(MI);
        if (MemRefBeginIdx < 0)
          return false;
        if (MO.getOperandNo() != static_cast<unsigned>(MemRefBeginIdx))
          return false;
        Uses.push_back(&MO);
      }
    }
  }
  return true;
}

void X86FunctionPrivateStacks::getPointerToFPSData(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, const DebugLoc &Loc, const GlobalValue *Member, Register Reg) {
  // MOV reg, [__fps_stackidx_<fn>] // NOTE: We should have already pre-scaled this in the FPS sanitizer runtime.
  // ADD reg, fs:[dtpoff(__fps_thd_stack<memb>)]
  BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), Reg)
      .addReg(X86::RIP)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addGlobalAddress(StackIdxSym)
      .addReg(X86::NoRegister);
  BuildMI(MBB, MBBI, Loc, TII->get(X86::ADD64rm), Reg)
      .addReg(Reg)
      .addReg(X86::NoRegister)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addGlobalAddress(Member, 0, X86II::MO_DTPOFF)
      .addReg(X86::FS);
}

void X86FunctionPrivateStacks::instrumentSetjmps(MachineFunction &MF) {
  const uint32_t *RegMask = TRI->getCallPreservedMask(MF, CallingConv::C);
  
  SmallVector<MachineInstr *> BuiltinSetjmps;
  for (MachineBasicBlock &MBB : MF)
    for (MachineInstr &MI : MBB)
      if (MI.getOpcode() == X86::EH_SjLj_Setup)
        BuiltinSetjmps.push_back(&MI);

  // NHM-FIXME: Format of EH_SjLj_Setup <bb> <regmask>
  for (MachineInstr *Setjmp : BuiltinSetjmps) {
    DebugLoc Loc;
    MachineBasicBlock *TargetMBB = Setjmp->getOperand(0).getMBB();

    // Insert call to __fps_ctx_alloc. Note that it's okay that the call
    // clobbers registers since EH_SjLj_Setup will clobber everything anyway.
    // NHM-FIXME: Add assert to verify this.
    // NHM-FIXME: Should probably move this afterwards?
    BuildMI(*Setjmp->getParent(), Setjmp->getIterator(), Loc, TII->get(X86::CALL64pcrel32))
        .addExternalSymbol("__fps_ctx_save")
        .addRegMask(RegMask);
    // NHM-FIXME: Make RAX implicit def?
    // NHM-FIXME: Make work with x86-32.
    const int CtxFI = MFI->CreateSpillStackObject(8, Align(8)); // NHM-FIXME: This shall not be moved to function-private stack!
    BuildMI(*Setjmp->getParent(), Setjmp->getIterator(), Loc, TII->get(X86::MOV64mr))
        .addFrameIndex(CtxFI)
        .addImm(1)
        .addReg(X86::NoRegister)
        .addImm(0)
        .addReg(X86::NoRegister)
        .addReg(X86::RAX);

    // At longjmp target, restore context.
    // NHM-FIXME: Assert no registers are live here.
    const auto TargetMBBI = TargetMBB->begin();
    BuildMI(*TargetMBB, TargetMBBI, Loc, TII->get(X86::MOV64rm), X86::RDI)
        .addFrameIndex(CtxFI)
        .addImm(1)
        .addReg(X86::NoRegister)
        .addImm(0)
        .addReg(X86::NoRegister);
    // NHM-FIXME: Make RDI implicit use?
    BuildMI(*TargetMBB, TargetMBBI, Loc, TII->get(X86::CALL64pcrel32))
        .addExternalSymbol("__fps_ctx_restore")
        .addRegMask(RegMask);
  }



  // Real C setjmps/longjmps.
  SmallVector<MachineInstr *> ExternalSetjmps;
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      if (!MI.isCall()) // NHM-FIXME: Are indirect calls considered to be indirect branches?
        continue;
      if (MI.mayLoadOrStore()) {
        assert(X86::getFirstAddrOperandIdx(MI) >= 0);
        continue;
      }
      const MachineOperand &MO = TII->getCalleeOperand(MI);
      if (!MO.isGlobal())
        continue;
      const Function *Callee = cast<Function>(MO.getGlobal());
      if (!Callee->hasFnAttribute(Attribute::ReturnsTwice))
        continue;
      ExternalSetjmps.push_back(&MI);
    }
  }

  for (MachineInstr *Setjmp : ExternalSetjmps) {
    DebugLoc Loc;
    MachineBasicBlock &MBB = *Setjmp->getParent();
    MachineBasicBlock::iterator MBBI = std::next(Setjmp->getIterator());
    const int CtxFI = MFI->CreateSpillStackObject(8, Align(8));

    BuildMI(MBB, MBBI, Loc, TII->get(X86::LEA64r), X86::RDI)
        .addFrameIndex(CtxFI)
        .addImm(1)
        .addReg(X86::NoRegister)
        .addImm(0)
        .addReg(X86::NoRegister);
    BuildMI(MBB, MBBI, Loc, TII->get(X86::COPY), X86::ESI)
        .addReg(X86::EAX); // NHM-FIXME: kill?
    BuildMI(MBB, MBBI, Loc, TII->get(X86::CALL64pcrel32))
        .addExternalSymbol("__fps_ctx_save_or_restore")
        .addRegMask(RegMask);
  }
  
}
  
bool X86FunctionPrivateStacks::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableFunctionPrivateStacks || MF.getName().starts_with("__fps_"))
    return false;

  TM = &MF.getTarget();

  const Module& M = *MF.getFunction().getParent();
  
  // For now, simply verify that stack realignment is not required,
  // and that we only need a stack pointer, not a base pointer or frame pointer.
  auto &STI = MF.getSubtarget<X86Subtarget>();
  TII = STI.getInstrInfo();
  TRI = STI.getRegisterInfo();
  MFI = &MF.getFrameInfo();

  // NHM-FIXME: Make it an assert?
  if (TRI->hasBasePointer(MF))
    report_fatal_error("No function should have base pointer with FPS enabled!");
  assert(!MFI->hasVarSizedObjects() && "All variable-sized stack objects should have been moved to the unsafe stack already!");

  StackIdxSym = M.getNamedValue(("__fps_stackidx_" + MF.getName()).str());
  ThdStackPtrsSym = M.getNamedValue("__fps_thd_stackptrs");
  assert(StackIdxSym && ThdStackPtrsSym);
  // NHM-FIXME: Assertions.

  DebugLoc Loc;

  DenseMap<int, uint64_t> PrivateFrameInfo;
  SmallVector<MachineInstr *> PrivateFrameAccesses;
  uint64_t PrivateFrameSize = 0;
  Align PrivateFrameAlign;
  for (int FI = MFI->getObjectIndexBegin(); FI < MFI->getObjectIndexEnd(); ++FI) {
    if (MFI->isFixedObjectIndex(FI))
      continue;
    SmallVector<MachineOperand *> Uses;
    if (!frameIndexOnlyUsedInMemoryOperands(FI, MF, Uses)) {
      LLVM_DEBUG(dbgs() << "skipping frame index " << FI << " which has a non-memory-operand use\n");
      continue;
    }
    if (Uses.empty())
      continue;

    Align ObjAlign = MFI->getObjectAlign(FI);
    PrivateFrameAlign = std::max(PrivateFrameAlign, ObjAlign);
    PrivateFrameSize = llvm::alignTo(PrivateFrameSize, ObjAlign);
    PrivateFrameInfo[FI] = PrivateFrameSize;
    assert(MFI->getObjectSize(FI) > 0);
    PrivateFrameSize += MFI->getObjectSize(FI);

    // Move uses to safe stack.
    for (MachineOperand *UseOp : Uses) {
      MachineInstr *MI = UseOp->getParent();
      PrivateFrameAccesses.push_back(MI);
    }
  }
  PrivateFrameSize = llvm::alignTo(PrivateFrameSize, PrivateFrameAlign);


  // Collect restore points for stack pointer.
  assignRegsForPrivateStackPointer(MF, PrivateFrameAccesses, PrivateFrameInfo);
  emitPrologue(MF, PrivateFrameSize);
  emitEpilogue(MF, PrivateFrameSize);

  for (MachineInstr *MI : PrivateFrameAccesses) {
    const int MemRefIdx = X86::getFirstAddrOperandIdx(*MI);
    assert(MemRefIdx >= 0);
    const MachineOperand &BaseMO = MI->getOperand(MemRefIdx + X86::AddrBaseReg);
    assert(BaseMO.isReg());
  }
    

#if 0
  // PROLOGUE: Private stack frame setup on function entry.
  MachineBasicBlock &EntryMBB = MF.front();
  MachineBasicBlock::iterator EntryMBBI = EntryMBB.begin();

  getPointerToFPSData(EntryMBB, EntryMBBI, Loc, ThdStackPtrsSym, X86::R15);
  BuildMI(EntryMBB, EntryMBBI, Loc, TII->get(X86::MOV64rm), X86::RBX)
      .addReg(X86::R15)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(0)
      .addReg(X86::NoRegister);
  // NHM-NOTE: Could also just sub from memory directly using SUB64mi32. Saves opcode bytes maybe + registers.
  // NHM-FIXME: Be smart about 8/32.
  BuildMI(EntryMBB, EntryMBBI, Loc, TII->get(X86::SUB64ri32), X86::RBX)
      .addReg(X86::RBX)
      .addImm(PrivateFrameSize);
  BuildMI(EntryMBB, EntryMBBI, Loc, TII->get(X86::MOV64mr))
      .addReg(X86::R15)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(0)
      .addReg(X86::NoRegister)
      .addReg(X86::RBX);
  // NHM-TEST:
  BuildMI(EntryMBB, EntryMBBI, Loc, TII->get(X86::MOV64mi32))
      .addReg(X86::RBX)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(-8)
      .addReg(X86::NoRegister)
      .addImm(0x42);

  // POST-CALL: Reload the private stack pointer after any indirect control-flow targets (ICTs).
  SmallVector<MachineInstr *> ICTs;
  SmallVector<MachineInstr *> Exits;
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      // NHM-FIXME: ENDBRANCHes haven't been inserted at this point, so the second half of the if condition does nothing.
      if ((MI.isCall() && !MI.isTerminator()) ||
          ((MI.getOpcode() == X86::ENDBR32 || MI.getOpcode() == X86::ENDBR64) && &MBB != &MF.front())) {
        ICTs.push_back(&MI);
      }
      // NHM-FIXME: Turn some of these into if-elses to speed up.
      if (MI.isReturn())
        Exits.push_back(&MI);
      // NHM-NOTE: This works only because we insert the SjLj instrumentation later.
      if (MI.getOpcode() == X86::EH_SjLj_Setup)
        ICTs.push_back(&MI.getOperand(0).getMBB()->front());
    }
  }
  for (MachineInstr *ICT : ICTs) {
    MachineBasicBlock &MBB = *ICT->getParent();
    const MachineBasicBlock::iterator MBBI = std::next(ICT->getIterator());
    getPointerToFPSData(MBB, MBBI, Loc, ThdStackPtrsSym, X86::RBX);
    BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), X86::RBX)
        .addReg(X86::RBX)
        .addImm(1)
        .addReg(X86::NoRegister)
        .addImm(0)
        .addReg(X86::NoRegister);
  }

  // EPILOGUE: Add back frame size.
  for (MachineInstr *Exit : Exits) {
    MachineBasicBlock &MBB = *Exit->getParent();
    const MachineBasicBlock::iterator MBBI = Exit->getIterator();
    getPointerToFPSData(MBB, MBBI, Loc, ThdStackPtrsSym, X86::R15);
    BuildMI(MBB, MBBI, Loc, TII->get(X86::ADD64ri32), X86::RBX)
        .addReg(X86::RBX)
        .addImm(PrivateFrameSize);
    BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64mr))
        .addReg(X86::R15)
        .addImm(1)
        .addReg(X86::NoRegister)
        .addImm(0)
        .addReg(X86::NoRegister)
        .addReg(X86::RBX);
  }
#endif


  // ======== ALL THIS STUFF IS FOR REFERENCE ONLY ========= //
  
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


  instrumentSetjmps(MF);

  return true;
}

}

INITIALIZE_PASS(X86FunctionPrivateStacks, PASS_KEY, "X86 Function Private Stacks", false, false)

FunctionPass *llvm::createX86FunctionPrivateStacksPass() {
  return new X86FunctionPrivateStacks();
}

char X86FunctionPrivateStacks::ID = 0;
