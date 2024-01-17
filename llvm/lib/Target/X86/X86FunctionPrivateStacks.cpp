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
  void loadPrivateStackPointer(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Reg, const DebugLoc &Loc = DebugLoc());
  void storePrivateStackPointer(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Reg, const DebugLoc &Loc = DebugLoc());

  bool frameIndexOnlyUsedInMemoryOperands(int FI, MachineFunction &MF, SmallVectorImpl<MachineOperand *> &Uses);
  void instrumentSetjmps(MachineFunction &MF);

  void partialRedundancyElimination(MachineFunction &MF, ArrayRef<MachineInstr *> Uses, ArrayRef<MachineInstr *> Kills, SmallVectorImpl<std::pair<MachineBasicBlock *, MachineBasicBlock::iterator>> &InsertPts);

  void assignRegsForPrivateStackPointer(MachineFunction &MF, ArrayRef<MachineInstr *> Uses);

  void makeRegsAvailable(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, SmallVectorImpl<MCPhysReg> &FreeRegs, unsigned NumRegsRequired);
};

void X86FunctionPrivateStacks::loadPrivateStackPointer(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Reg, const DebugLoc &Loc) {
  getPointerToFPSData(MBB, MBBI, Loc, ThdStackPtrsSym, Reg);
  BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), Reg)
      .addReg(Reg)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(0)
      .addReg(X86::NoRegister);
}

void X86FunctionPrivateStacks::makeRegsAvailable(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, SmallVectorImpl<MCPhysReg> &FreeRegs, unsigned NumRegsRequired) {
  MachineFunction &MF = *MBB.getParent();
  const MachineRegisterInfo &MRI = MF.getRegInfo();
  MachineFrameInfo &MFI = MF.getFrameInfo();

  // Get live-ins to MI. We use this to try to find free registers.
  LivePhysRegs LPR(*TRI);
  LPR.addLiveOuts(MBB);
  for (MachineInstr &LiveMI : reverse(MBB)) {
    LPR.stepBackward(LiveMI);
    if (LiveMI.getIterator() == MBBI)
      break;
  }

  // Try to get as many free regs as possible.
  unsigned NumRegsFreed = 0;
  for (; NumRegsFreed < NumRegsRequired; ++NumRegsFreed) {
    auto it = find_if(X86::GR64RegClass, [&] (MCPhysReg Reg) -> bool {
      return LPR.available(MRI, Reg);
    });
    if (it == std::end(X86::GR64RegClass))
      break;
    FreeRegs.push_back(*it);
  }
  if (NumRegsFreed == NumRegsRequired)
    return;

  assert(!MBB.empty());

  // Remove uses from live-ins to MI to get spill candidate set.
  MachineInstr &MI = *MBBI;
  for (const MachineOperand &MO : MI.operands())  // NHM-FIXME: uses()?
    if (MO.isReg() && MO.isUse() && MO.getReg() != X86::NoRegister)
      LPR.removeReg(MO.getReg());

  // Try to spill registers around MI.

  auto getSpillableReg = [&] (const LivePhysRegs &LPR) -> MCPhysReg {
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

  // NHM-FIXME: Should return full reg.n
  auto getSpillRegs = [&] (const LivePhysRegs &LPR, SmallVectorImpl<MCPhysReg> &SpillRegs) -> MCPhysReg {
    Register SpillRegFull = getSpillableReg(LPR);
    if (SpillRegFull == X86::NoRegister) {
    } else if (LPR.contains(SpillRegFull)) {
      SpillRegs.push_back(SpillRegFull);
    } else if (Register SpillReg32 = getX86SubSuperRegister(SpillRegFull, 32); LPR.contains(SpillReg32)) {
      SpillRegs.push_back(SpillReg32);
    } else if (Register SpillReg16 = getX86SubSuperRegister(SpillRegFull, 16); LPR.contains(SpillReg16)) {
      SpillRegs.push_back(SpillReg16);
    } else {
      Register SpillReg8H = getX86SubSuperRegister(SpillRegFull, 8, /*High*/true);
      if (LPR.contains(SpillReg8H))
        SpillRegs.push_back(SpillReg8H);
      Register SpillReg8L = getX86SubSuperRegister(SpillRegFull, 8, /*High*/false);
      if (LPR.contains(SpillReg8L))
        SpillRegs.push_back(SpillReg8L);
    }
    return SpillRegFull;
  };
  
  
  for (; NumRegsFreed < NumRegsRequired; ++NumRegsFreed) {
    SmallVector<MCPhysReg, 2> SpillRegs;
    MCPhysReg FreeReg = getSpillRegs(LPR, SpillRegs);
    if (FreeReg == X86::NoRegister)
      report_fatal_error("Cannot spill any registers at this point!");

    for (MCPhysReg SpillReg : SpillRegs) {
      const auto *RC = TRI->getMinimalPhysRegClass(SpillReg);
      unsigned SpillSize = TRI->getSpillSize(*RC);
      int FI = MFI.CreateSpillStackObject(SpillSize, Align(SpillSize));
      TII->storeRegToStackSlot(MBB, MBBI, SpillReg, true, FI, RC, TRI, X86::NoRegister);
      TII->loadRegFromStackSlot(MBB, std::next(MBBI), SpillReg, FI, RC, TRI, X86::NoRegister);
      LPR.removeReg(SpillReg);
    }

    assert(LPR.available(MRI, FreeReg));

    FreeRegs.push_back(FreeReg);
  }
}

void X86FunctionPrivateStacks::partialRedundancyElimination(MachineFunction &MF, ArrayRef<MachineInstr *> Uses, ArrayRef<MachineInstr *> Kills, SmallVectorImpl<std::pair<MachineBasicBlock *, MachineBasicBlock::iterator>> &InsertPts) {
  struct InOut {
    bool In;
    bool Out;

    bool operator==(const InOut &Other) const {
      return In == Other.In && Out == Other.Out;
    }
  };

  // ANTICIPATED EXPRESSIONS
  std::map<MachineBasicBlock *, InOut> AnticipatedMBBs;
  std::map<MachineInstr *, InOut> AnticipatedMIs;

  // Iniitalize
  for (MachineBasicBlock &MBB : MF) {
    auto& AnticipatedMBB = AnticipatedMBBs[&MBB];
    AnticipatedMBB.In = true;
    AnticipatedMBB.Out = !MBB.succ_empty();
    for (MachineInstr &MI : MBB) {
      auto &AnticipatedMI = AnticipatedMIs[&MI];
      AnticipatedMI.In = true;
      AnticipatedMI.Out = true;
    }
  }

  // Run data-flow
  while (true) {
    const auto BakMBBs = AnticipatedMBBs;
    const auto BakMIs = AnticipatedMIs;

    for (MachineBasicBlock &MBB : MF) {
      auto &AnticipatedMBB = AnticipatedMBBs[&MBB];

      // Meet OUT[MBB].
      for (MachineBasicBlock *Succ : MBB.successors())
        AnticipatedMBB.Out &= AnticipatedMBBs[Succ].In;

      // Transfer instructions.
      for (MachineInstr &MI : reverse(MBB)) {
        auto &AnticipatedMI = AnticipatedMIs[&MI];

        // Compute OUT.
        if (MachineInstr *Succ = MI.getNextNode())
          AnticipatedMI.Out = AnticipatedMIs[Succ].In;
        else
          AnticipatedMI.Out = AnticipatedMBB.Out;

        // Transfer IN.
        AnticipatedMI.In = AnticipatedMI.Out;
        if (is_contained(Kills, &MI))
          AnticipatedMI.In = false;
        if (is_contained(Uses, &MI))
          AnticipatedMI.In = true;
      }

      // Compute IN[MBB].
      if (MBB.empty())
        AnticipatedMBB.In = AnticipatedMBB.Out;
      else
        AnticipatedMBB.In = AnticipatedMIs[&MBB.front()].In;
      
    }

    if (BakMBBs == AnticipatedMBBs && BakMIs == AnticipatedMIs)
      break;
  }


  // AVAILBLE EXPRESSIONS
  std::map<MachineBasicBlock *, InOut> AvailableMBBs;
  std::map<MachineInstr *, InOut> AvailableMIs;

  // Initialization.
  for (MachineBasicBlock &MBB : MF) {
    auto &AvailableMBB = AvailableMBBs[&MBB];
    AvailableMBB.In = !MBB.pred_empty();
    AvailableMBB.Out = true;
    for (MachineInstr &MI : MBB) {
      auto &AvailableMI = AvailableMIs[&MI];
      AvailableMI.In = true;
      AvailableMI.Out = true;
    }
  }

  // Run data-flow
  while (true) {
    const auto BakMBBs = AvailableMBBs;
    const auto BakMIs = AvailableMIs;

    for (MachineBasicBlock &MBB : MF) {
      auto &AvailableMBB = AvailableMBBs[&MBB];

      // Meet IN[MBB].
      for (MachineBasicBlock *Pred : MBB.predecessors())
        AvailableMBB.In &= AvailableMBBs[Pred].Out;

      // Transfer instructions.
      for (MachineInstr &MI : MBB) {
        auto &AvailableMI = AvailableMIs[&MI];
        
        // Compute IN[MI]
        if (MachineInstr *Pred = MI.getPrevNode())
          AvailableMI.In = AvailableMIs[Pred].Out;
        else
          AvailableMI.In = AvailableMBB.In;

        // Transfer OUT[MI]
        AvailableMI.Out = (AvailableMI.In || AnticipatedMIs[&MI].In) && !is_contained(Kills, &MI);
      }

      // Compute OUT[MBB]
      if (MBB.empty())
        AvailableMBB.Out = AvailableMBB.In;
      else
        AvailableMBB.Out = AvailableMIs[&MBB.back()].Out;
    }

    if (BakMBBs == AvailableMBBs && BakMIs == AvailableMIs)
      break;
  }
  
  // Find the final insertion points.
  for (MachineBasicBlock &MBB : MF) {
    if (MBB.empty()) {
      if (AnticipatedMBBs[&MBB].In && !AvailableMBBs[&MBB].In)
        InsertPts.emplace_back(&MBB, MBB.begin());
    } else {
      for (MachineInstr &MI : MBB) {
        if (AnticipatedMIs[&MI].In && !AvailableMIs[&MI].In)
          InsertPts.emplace_back(&MBB, MI.getIterator());
      }
    }
  }
  
}

void X86FunctionPrivateStacks::assignRegsForPrivateStackPointer(MachineFunction &MF, ArrayRef<MachineInstr *> Uses) {
 
  const MachineRegisterInfo &MRI = MF.getRegInfo();
  MachineFrameInfo &MFI = MF.getFrameInfo();

  auto getFreeReg = [&] (const LivePhysRegs &LPR) -> Register {
    auto it = find_if(X86::GR64RegClass, [&] (MCPhysReg Reg) -> bool {
      return LPR.available(MRI, Reg);
    });
    if (it == std::end(X86::GR64RegClass))
      return X86::NoRegister;
    else
      return *it;
  };

  auto hasFreeReg = [&] (const LivePhysRegs &LPR) -> bool {
    return getFreeReg(LPR) != X86::NoRegister;
  };

  auto getSpillableReg = [&] (const LivePhysRegs &LPR) -> Register {
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

  // NHM-FIXME: Should return full reg.n
  auto getSpillRegs = [&] (const LivePhysRegs &LPR, SmallVectorImpl<Register> &SpillRegs) {
    Register SpillRegFull = getSpillableReg(LPR);
    assert(SpillRegFull != X86::NoRegister);
    if (LPR.contains(SpillRegFull)) {
      SpillRegs.push_back(SpillRegFull);
      return;
    }
    Register SpillReg32 = getX86SubSuperRegister(SpillRegFull, 32);
    if (LPR.contains(SpillReg32)) {
      SpillRegs.push_back(SpillReg32);
      return;
    }
    Register SpillReg16 = getX86SubSuperRegister(SpillRegFull, 16);
    if (LPR.contains(SpillReg16)) {
      SpillRegs.push_back(SpillReg16);
      return;
    }
    Register SpillReg8H = getX86SubSuperRegister(SpillRegFull, 8, /*High*/true);
    if (LPR.contains(SpillReg8H))
      SpillRegs.push_back(SpillReg8H);
    Register SpillReg8L = getX86SubSuperRegister(SpillRegFull, 8, /*High*/false);
    if (LPR.contains(SpillReg8L))
      SpillRegs.push_back(SpillReg8L);
  };

  auto checkUses = [&] () {
    for (MachineInstr *Use : Uses) {
      MachineBasicBlock &MBB = *Use->getParent();
      LivePhysRegs LPR(*TRI);
      LPR.addLiveOuts(MBB);
      for (MachineInstr &MI : reverse(MBB)) {
        LPR.stepBackward(MI);
        if (&MI == Use)
          break;
      }
      if (!hasFreeReg(LPR)) {
        LLVM_DEBUG(dbgs() << "use does not have free reg: " << *Use);
      }
      assert(hasFreeReg(LPR));
    }
  };
  

#if 0
  // Step 0: Guarantee that at least one register for PSP allocation at each PSP use.
  for (MachineInstr *Use : Uses) {
    MachineBasicBlock &MBB = *Use->getParent();

    LivePhysRegs LPR(*TRI);
    LPR.addLiveOuts(MBB);
    for (MachineInstr &MI : reverse(MBB)) {
      LPR.stepBackward(MI);
      if (&MI == Use)
        break;
    }

    if (hasFreeReg(LPR))
      continue;

    // If it doesn't have a free register, we need to safely spill one.
    // We can spill a register that is not used by the instruction.
    if (Use->isCall())
      report_fatal_error("PSP used in call instruction with no free regs");
    SmallVector<std::pair<MCPhysReg, const MachineOperand *>> Clobbers;
    // Remove uses.
    for (const MachineOperand &MO : Use->operands()) // NHM-FIXME: uses()?
      if (MO.isReg() && MO.isUse() && MO.getReg() != X86::NoRegister)
        LPR.removeReg(MO.getReg());
    SmallVector<Register> RegsToSpill;
    getSpillRegs(LPR, RegsToSpill);
    assert(!RegsToSpill.empty());
    auto MBBI = Use->getIterator();
    for (Register RegToSpill : RegsToSpill) {
      const auto *RC = TRI->getMinimalPhysRegClass(RegToSpill);
      unsigned SpillSize = TRI->getSpillSize(*RC);
      int FI = MFI.CreateSpillStackObject(SpillSize, Align(SpillSize));
      TII->storeRegToStackSlot(MBB, MBBI, RegToSpill, true, FI, RC, TRI, X86::NoRegister);
      TII->loadRegFromStackSlot(MBB, std::next(MBBI), RegToSpill, FI, RC, TRI, X86::NoRegister);
      // NHM-FIXME: Insert LFENCE + ZERO.
      
      LLVM_DEBUG(dbgs() << "spilled register " << TRI->getRegAsmName(RegToSpill) << " for instruction " << *Use);
    }
    
  }
#endif

  // Construct kils.
  SmallVector<MachineInstr *> Kills;
  SmallVector<MachineInstr *> Tmps;
  SmallSet<MachineBasicBlock *, 8> KilledOnEntry;
  for (MachineBasicBlock &MBB : MF) {
    LivePhysRegs LPR(*TRI);
    LPR.addLiveOuts(MBB);

    auto hasFreeReg = [&] (const LivePhysRegs &LPR) -> bool {
      return any_of(X86::GR64RegClass, [&] (MCPhysReg Reg) -> bool {
        return LPR.available(MRI, Reg);
      });
    };

    for (MachineInstr &MI : reverse(MBB)) {
      // If no registers are free, then treat it as kill.
      LPR.addUses(MI);
      if (!hasFreeReg(LPR))
        Kills.push_back(&MI);

      // Calls are always kills.
      if (MI.isCall())
        Kills.push_back(&MI);

      LPR.stepBackward(MI);
    }

    if (MBB.hasAddressTaken())
      KilledOnEntry.insert(&MBB);

    // Check live ins.
    LPR.clear();
    LPR.addLiveIns(MBB);
    for (MachineBasicBlock *Pred : MBB.predecessors())
      LPR.addLiveOuts(*Pred);
    if (!hasFreeReg(LPR))
      KilledOnEntry.insert(&MBB);
  }
  if (const MachineJumpTableInfo *JTI = MF.getJumpTableInfo())
    for (const MachineJumpTableEntry &JTE : JTI->getJumpTables())
      for (MachineBasicBlock *MBB : JTE.MBBs)
        KilledOnEntry.insert(MBB);
  for (MachineBasicBlock *MBB : KilledOnEntry) {
    MachineInstr *Tmp = BuildMI(*MBB, MBB->begin(), DebugLoc(), TII->get(X86::NOOP));
    Tmps.push_back(Tmp);
    Kills.push_back(Tmp);
  }

  SmallVector<std::pair<MachineBasicBlock *, MachineBasicBlock::iterator>> InsertPts;
  partialRedundancyElimination(MF, Uses, Kills, InsertPts);



  // Insert loads of PSP.
  // Spill registers as needed.
  // NHM-FIXME: Should use an iterative algorithm to reduce spills and maximize spilled intervals.
  // NHM-FIXME: Need to be able step forward too! Assert it's identical in both directions.
  for (const auto &[MBB, MBBI] : InsertPts) {
    LivePhysRegs LPR(*TRI);
    LPR.addLiveOuts(*MBB);
    for (MachineInstr &MI : reverse(*MBB)) {
      LPR.stepBackward(MI);
      if (MI.getIterator() == MBBI)
        break;
    }
    
    // Check how many registers we need
    //  if EFLAGS not live -> 1
    //  if EFLAGS live -> 2
    int NumRegsRequired = LPR.contains(X86::EFLAGS) ? 2 : 1;

    // Get free regs for our use.
    SmallVector<MCPhysReg, 2> FreeRegs;
    makeRegsAvailable(*MBB, MBBI, FreeRegs, 2);
    
    
#if 0
    LPR.addLiveIns(*MBB);
    for (auto LiveMBBI = MBB->begin(); LiveMBBI != MBBI; ++LiveMBBI) {
      SmallVector<std::pair<MCPhysReg, const MachineOperand *>> Clobbers;
      LPR.stepForward(*LiveMBBI, Clobbers);
    }
#else
    // NHM-FIXME: Should be able to step forward too!
    LPR.addLiveOuts(*MBB);
    for (MachineInstr &MI : reverse(*MBB)) {
      LPR.stepBackward(MI);
      if (MI.getIterator() == MBBI)
        break;
    }
#endif

#if 0
    auto RegIt = find_if(X86::GR64RegClass, [&] (MCPhysReg Reg) -> bool {
      return LPR.available(MRI, Reg);
    });
    assert(RegIt != std::end(X86::GR64RegClass));
    loadPrivateStackPointer(*MBB, MBBI, *RegIt);
#endif
  }  

  // Erase temporary instructions.
  // NOTE: This should go last.
  for (MachineInstr *Tmp : Tmps)
    Tmp->eraseFromParent();
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
  auto &MRI = MF.getRegInfo();

  // NHM-FIXME: Make it an assert?
  if (TRI->hasBasePointer(MF))
    report_fatal_error("No function should have base pointer with FPS enabled!");
#if 0
  assert(MRI.reg_empty(X86::RBX) && "Expected no existing uses of RBX for functions requiring a private stack!");
#endif
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
      const unsigned MemRefIdxBegin = UseOp->getOperandNo() - X86::AddrBaseReg;
      MachineOperand &BaseOp = MI->getOperand(MemRefIdxBegin + X86::AddrBaseReg);
      MachineOperand &ScaleOp = MI->getOperand(MemRefIdxBegin + X86::AddrScaleAmt);
      MachineOperand &IndexOp = MI->getOperand(MemRefIdxBegin + X86::AddrIndexReg);
      MachineOperand &DispOp = MI->getOperand(MemRefIdxBegin + X86::AddrDisp);
      MachineOperand &SegmentOp = MI->getOperand(MemRefIdxBegin + X86::AddrSegmentReg);

#if 0
      BaseOp.ChangeToRegister(X86::RBX, /*isDef*/false);
      DispOp.setImm(DispOp.getImm() + PrivateFrameOffset);
#endif
      PrivateFrameAccesses.push_back(MI);
    }
  }
  PrivateFrameSize = llvm::alignTo(PrivateFrameSize, PrivateFrameAlign);


  // Collect restore points for stack pointer.
  assignRegsForPrivateStackPointer(MF, PrivateFrameAccesses);

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
