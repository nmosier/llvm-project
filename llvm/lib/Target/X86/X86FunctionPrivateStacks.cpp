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

cl::opt<bool> EnableOverflowChecks(
    PASS_KEY "-check-overflow",
    cl::desc("Enable overflow checks"), // NHM-FIXME
    cl::init(false),
    cl::Hidden);

cl::opt<bool> FPSParanoid(
    PASS_KEY "-paranoid",
    cl::desc("Perform additional checks to prevent unlikely attack scenarios. "
             "Currently this flag only causes the insertion of bounds checks."),
    cl::init(false),
    cl::Hidden);
    

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
  const GlobalValue *ThdStacksSym;

  // NHM-FIXME: No longer need pointer to member.
  void getPointerToFPSData(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, const DebugLoc &Loc, const GlobalValue *Member, Register Reg);

  // NOTE: Permits PtrReg == ValReg.
  void loadPrivateStackPointer(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Reg, const DebugLoc &Loc = DebugLoc());

  // NOTE: Does not permit PtrReg == ValReg.
  void storePrivateStackPointer(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Reg, const DebugLoc &Loc = DebugLoc());

  bool frameIndexOnlyUsedInMemoryOperands(int FI, MachineFunction &MF, SmallVectorImpl<MachineOperand *> &Uses);
  bool instrumentSetjmps(MachineFunction &MF);

  void partialRedundancyElimination(MachineFunction &MF, ArrayRef<MachineInstr *> Uses, ArrayRef<MachineInstr *> Kills, SmallVectorImpl<std::pair<MachineBasicBlock *, MachineBasicBlock::iterator>> &InsertPts);

  void assignRegsForPrivateStackPointer(MachineFunction &MF, ArrayRef<MachineInstr *> Uses, const DenseMap<int, uint64_t>& PrivateFrameInfo);
  // NHM-OPT: Could make it a fixed-size stack frame at first, set a flag in a thread-local variable __fps_stacktypes.
  void emitRegStack(MachineFunction &MF);
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
  
  MachineBasicBlock &EntryMBB = MF.front();
  auto EntryMBBI = EntryMBB.begin();
  const auto &MRI = MF.getRegInfo();

  SmallVector<MCPhysReg, 2> Regs;
  LivePhysRegs LPR(*TRI);
  LPR.addLiveIns(EntryMBB);
  if (!getFreeRegs(LPR, MRI, 2, Regs))
    report_fatal_error("Failed to get free registers for FPS prologue!");
  assert(Regs.size() == 2);
  assert(!LPR.contains(X86::EFLAGS));

  const uint32_t *RegMask = TRI->getCallPreservedMask(MF, CallingConv::C);
  DebugLoc Loc;

  MachineBasicBlock &NewEntryMBB = *MF.CreateMachineBasicBlock();
  MachineBasicBlock &CheckMBB = *MF.CreateMachineBasicBlock();
  MachineBasicBlock &AllocMBB = *MF.CreateMachineBasicBlock();
  MF.push_front(&CheckMBB);
  MF.push_front(&NewEntryMBB);
  MF.push_back(&AllocMBB);
  for (const auto &LI : EntryMBB.liveins()) {
    CheckMBB.addLiveIn(LI);
    AllocMBB.addLiveIn(LI);
    NewEntryMBB.addLiveIn(LI);
  }
  EntryMBB.addLiveIn(Regs[0]);
  EntryMBB.addLiveIn(Regs[1]);
  NewEntryMBB.addSuccessor(&CheckMBB);

  // CheckMBB:
  //  fps_t *r0 <- get fps pointer
  //  if (r0->stackbase == 0)
  //    AllocMBB
  getPointerToFPSData(CheckMBB, CheckMBB.end(), Loc, ThdStacksSym, Regs[0]);
  BuildMI(CheckMBB, CheckMBB.end(), Loc, TII->get(X86::MOV64rm), Regs[1])
      .addReg(Regs[0])
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(0) // NHM-FIXME: Symbolize
      .addReg(X86::NoRegister);
  BuildMI(CheckMBB, CheckMBB.end(), Loc, TII->get(X86::OR64rr), Regs[1])
      .addReg(Regs[1])
      .addReg(Regs[1]);
  TII->insertBranch(CheckMBB, &AllocMBB, &EntryMBB, {MachineOperand::CreateImm(X86::COND_E)}, DebugLoc());
  CheckMBB.addSuccessor(&AllocMBB);
  CheckMBB.addSuccessor(&EntryMBB);


  // AllocMBB:
  //   save callee-saved registers
  //   __fps_allocstack(__fps_stackidx_<name>);
  //   restore callee-saved regsiters
  //   jmp CheckMBB
  BuildMI(AllocMBB, AllocMBB.end(), DebugLoc(), TII->get(X86::MOV64rm), X86::RDI)
      .addReg(X86::RIP)
      .addImm(1)
      .addReg(0)
      .addGlobalAddress(StackIdxSym)
      .addReg(0);
  BuildMI(AllocMBB, AllocMBB.end(), DebugLoc(), TII->get(X86::CALL64pcrel32))
      .addExternalSymbol("__fps_allocstack")
      .addRegMask(RegMask)
      .addUse(X86::RDI, RegState::ImplicitKill);
  MFI->setAdjustsStack(true);
  MFI->setHasCalls(true);

  const auto AllocPreMBBI = AllocMBB.begin();
  for (auto &LI : AllocMBB.liveins()) {
    const auto Reg = LI.PhysReg;
    const auto *RC = TRI->getMinimalPhysRegClass(Reg);
    int FI = MFI->CreateSpillStackObject(TRI->getSpillSize(*RC), TRI->getSpillAlign(*RC));
    TII->storeRegToStackSlot(AllocMBB, AllocPreMBBI, Reg, true, FI, RC, TRI, X86::NoRegister);
    TII->loadRegFromStackSlot(AllocMBB, AllocMBB.end(), Reg, FI, RC, TRI, X86::NoRegister);
  }
  TII->insertUnconditionalBranch(AllocMBB, &CheckMBB, DebugLoc());  
  AllocMBB.addSuccessor(&CheckMBB);

  // EntryMBB:
  //  void *r1 = r1->stackptr;
  //  r1 = r1 - PrivateFrameSize;
  //  r0->stackptr = r1;
  BuildMI(EntryMBB, EntryMBBI, Loc, TII->get(X86::SUB64ri32), Regs[1])
      .addReg(Regs[1])
      .addImm(PrivateFrameSize);
  auto *DummyVar = MF.getFunction().getParent()->getNamedValue(("__fps_dummy_" + MF.getName()).str());
  assert(DummyVar);
  BuildMI(EntryMBB, EntryMBBI, DebugLoc(), TII->get(X86::CMOV64rm), Regs[1])
      .addReg(Regs[1])
      .addReg(X86::RIP)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addGlobalAddress(DummyVar)
      .addReg(X86::NoRegister)
      .addImm(X86::COND_B); // If carry flag was set, then the input was zero, or we have a huge frame that jumped over the guard.
  // Either way, the sae behavior is to load in the dummy value.
  if (EnableOverflowChecks) {
    BuildMI(EntryMBB, EntryMBBI, Loc, TII->get(X86::CMP64rm))
        .addReg(Regs[1])
        .addReg(Regs[0])
        .addImm(1)
        .addReg(X86::NoRegister)
        .addImm(8) // NHM-FIXME: symbolize
        .addReg(X86::NoRegister);
    BuildMI(EntryMBB, EntryMBBI, Loc, TII->get(X86::CMOV64rm), Regs[1])
        .addReg(Regs[1])
        .addReg(X86::RIP)
        .addImm(1)
        .addReg(X86::NoRegister)
        .addGlobalAddress(DummyVar)
        .addReg(X86::NoRegister)
        .addImm(X86::COND_B);
  }
  BuildMI(EntryMBB, EntryMBBI, DebugLoc(), TII->get(X86::MOV64mr))
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

    getPointerToFPSData(MBB, MBBI, DebugLoc(), ThdStacksSym, Regs[0]);
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
        // MOV r1, [rip+gottpoff(__fps_thd_stackptrs@gottpoff)]
        // MOV r1, fs:[r1]
        // MOV r2, [rip+__stackidx_<fn>]
        DebugLoc Loc;
        BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), ScratchReg)
            .addReg(X86::RIP)
            .addImm(1)
            .addReg(X86::NoRegister)
            .addGlobalAddress(ThdStacksSym, 0, X86II::MO_GOTTPOFF)
            .addReg(X86::NoRegister);
        BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), ScratchReg)
            .addReg(ScratchReg)
            .addImm(1)
            .addReg(X86::NoRegister)
            .addImm(0)
            .addReg(X86::FS);
        BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::MOV64rm), PSPReg)
            .addReg(X86::RIP)
            .addImm(1)
            .addReg(X86::NoRegister)
            .addGlobalAddress(StackIdxSym)
            .addReg(X86::NoRegister);
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
  getPointerToFPSData(MBB, MBBI, Loc, ThdStacksSym, Reg);
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
  // MOV reg, [rip+gottpoff(__fps_thd_stackptrs@gottpoff)]
  // MOV reg, fs:[reg]
  // ADD reg, [rip+__stackidx_<fn>]
  BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), Reg)
      .addReg(X86::RIP)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addGlobalAddress(Member, 0, X86II::MO_GOTTPOFF)
      .addReg(X86::NoRegister);
  BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), Reg)
      .addReg(Reg)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(0)
      .addReg(X86::FS);
  BuildMI(MBB, MBBI, Loc, TII->get(X86::ADD64rm), Reg)
      .addReg(Reg)
      .addReg(X86::RIP)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addGlobalAddress(StackIdxSym)
      .addReg(X86::NoRegister);
}

bool X86FunctionPrivateStacks::instrumentSetjmps(MachineFunction &MF) {
  // Does this function have setjmps?
  SmallVector<MachineInstr *> BuiltinSetjmps, ExternalSetjmps;
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      if (MI.getOpcode() == X86::EH_SjLj_Setup) {
        BuiltinSetjmps.push_back(&MI);
        continue;
      }
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

  if (BuiltinSetjmps.empty() && ExternalSetjmps.empty())
    return false;

  const uint32_t *RegMask = TRI->getCallPreservedMask(MF, CallingConv::C);

  // Allocate context stack slot at function entrypoint and zero-initialize.
  const int CtxFI = MFI->CreateSpillStackObject(8, Align(8));
  BuildMI(MF.front(), MF.front().begin(), DebugLoc(), TII->get(X86::MOV64mi32))
      .addFrameIndex(CtxFI)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(0)
      .addReg(X86::NoRegister)
      .addImm(0);

  // Pop context on return.
  for (MachineBasicBlock &MBB : MF) {
    if (!MBB.succ_empty())
      continue;
    assert(!MBB.empty());
    MachineInstr &Ret = MBB.back();
    if (!Ret.isReturn())
      continue;
    const auto MBBI = Ret.getIterator();

    LivePhysRegs LPR(*TRI);
    LPR.addLiveOuts(MBB);
    LPR.stepBackward(Ret);
    SmallVector<std::pair<MCPhysReg, int>> FIs;
    for (const MachineOperand &MO : Ret.uses()) {
      if (MO.isReg() && MO.isUse()) {
        const auto Reg = MO.getReg();
        const auto *RC = TRI->getMinimalPhysRegClass(Reg);
        const auto FI = MFI->CreateSpillStackObject(TRI->getSpillSize(*RC), TRI->getSpillAlign(*RC));
        FIs.emplace_back(Reg, FI);
        TII->storeRegToStackSlot(MBB, MBBI, Reg, /*isKill*/true, FI, RC, TRI, X86::NoRegister);
      }
    }
    TII->loadRegFromStackSlot(MBB, MBBI, X86::RDI, CtxFI, &X86::GR64RegClass, TRI, X86::NoRegister);
    BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::CALLpcrel32))
        .addExternalSymbol("__fps_ctx_pop")
        .addRegMask(RegMask)
        .addUse(X86::RDI, RegState::ImplicitKill);
    for (const auto &[Reg, FI] : FIs) {
      TII->loadRegFromStackSlot(MBB, MBBI, Reg, FI, TRI->getMinimalPhysRegClass(Reg), TRI, X86::NoRegister);
    }
  }
  
  // NHM-FIXME: Format of EH_SjLj_Setup <bb> <regmask>
  for (MachineInstr *Setjmp : BuiltinSetjmps) {
    DebugLoc Loc;
    MachineBasicBlock *TargetMBB = Setjmp->getOperand(0).getMBB();

    // Entry: MOV [old.FI], nullptr
    // 
    // MOV %rdi, old.FI
    // CALLpcrel32 __fps_ctx_save(%rdi=old) 
    // EH_SjLj_Setup target <regmask>
    //
    // target:
    

    // Insert call to __fps_ctx_alloc. Note that it's okay that the call
    // clobbers registers since EH_SjLj_Setup will clobber everything anyway.
    // NHM-FIXME: Add assert to verify this.
    // NHM-FIXME: Should probably move this afterwards?
    TII->loadRegFromStackSlot(*Setjmp->getParent(), Setjmp->getIterator(), X86::RDI, CtxFI, &X86::GR64RegClass, TRI, X86::NoRegister);
    BuildMI(*Setjmp->getParent(), Setjmp->getIterator(), Loc, TII->get(X86::CALL64pcrel32))
        .addExternalSymbol("__fps_ctx_push")
        .addRegMask(RegMask)
        .addUse(X86::RDI, RegState::ImplicitKill)
        .addDef(X86::RAX, RegState::Implicit);
    TII->storeRegToStackSlot(*Setjmp->getParent(), Setjmp->getIterator(), X86::RAX, /*isKill*/true, CtxFI, &X86::GR64RegClass, TRI, X86::NoRegister);

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
        .addRegMask(RegMask)
        .addUse(X86::RDI, RegState::ImplicitKill);
  }



  // Real C setjmps/longjmps.
  for (MachineInstr *Setjmp : ExternalSetjmps) {
    DebugLoc Loc;
    MachineBasicBlock &MBB = *Setjmp->getParent();
    MachineBasicBlock::iterator MBBI = std::next(Setjmp->getIterator());

    // NHM-FIXME: Assert we're not clobbering additional registers here. 
    BuildMI(MBB, MBBI, Loc, TII->get(X86::LEA64r), X86::RDI)
        .addFrameIndex(CtxFI)
        .addImm(1)
        .addReg(X86::NoRegister)
        .addImm(0)
        .addReg(X86::NoRegister);
    BuildMI(MBB, MBBI, Loc, TII->get(X86::COPY), X86::ESI)
        .addReg(X86::EAX); // NHM-FIXME: kill?
    BuildMI(MBB, MBBI, Loc, TII->get(X86::CALL64pcrel32))
        .addExternalSymbol("__fps_ctx_push_or_restore")
        .addRegMask(RegMask)
        .addUse(X86::RDI, RegState::ImplicitKill)
        .addUse(X86::ESI, RegState::ImplicitKill)
        .addDef(X86::EAX, RegState::Implicit);
  }


  return true;
}
  
bool X86FunctionPrivateStacks::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableFunctionPrivateStacks || MF.getName().starts_with("__fps_"))
    return false;  
  
  TM = &MF.getTarget();

  const Function &F = MF.getFunction();
  const Module &M = *F.getParent();
  
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
  ThdStacksSym = M.getNamedValue("__fps_thd_stacks");
  assert(StackIdxSym && ThdStacksSym);
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

  // Erase unused stack slots.
  for (const auto &[FI, _] : PrivateFrameInfo)
    MFI->RemoveStackObject(FI);

  MF.verify();

  instrumentSetjmps(MF);

  // Update register.
  GlobalVariable *FrameSizeVar = cast<GlobalVariable>(M.getNamedValue(("__fps_framesize_" + F.getName()).str()));
  FrameSizeVar->setInitializer(ConstantInt::get(IntegerType::get(M.getContext(), 64), PrivateFrameSize));

  return true;
}

}

INITIALIZE_PASS(X86FunctionPrivateStacks, PASS_KEY, "X86 Function Private Stacks", false, false)

FunctionPass *llvm::createX86FunctionPrivateStacksPass() {
  return new X86FunctionPrivateStacks();
}

char X86FunctionPrivateStacks::ID = 0;
