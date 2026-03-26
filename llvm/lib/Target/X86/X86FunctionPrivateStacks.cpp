#include "llvm/CodeGen/FunctionPrivateStacks.h" // NHM-TODO: Maybe don't need this?

#include "MCTargetDesc/X86MCTargetDesc.h"
#include "X86.h"
#include "X86InstrInfo.h"
#include "X86RegisterInfo.h"
#include "X86Subtarget.h"
#include "llvm/IR/Module.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "MCTargetDesc/X86BaseInfo.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/CodeGen/RegisterScavenging.h"
#include "llvm/CodeGen/RegAllocPBQP.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/TargetFunctionPrivateStacks.h"

using namespace llvm;

#define PASS_KEY "x86-fps"
#define DEBUG_TYPE PASS_KEY

namespace {

// NHM-FIXME: Is this used?
cl::opt<bool> EnableOverflowChecks(
    PASS_KEY "-check-overflow",
    cl::desc("Enable overflow checks"), // NHM-FIXME
    cl::init(false),
    cl::Hidden);

// NHM-FIXME: Make this a shared flag and move to the CodeGen pass.

// NHM-FIXME: Move to more sane location.
// NHM-FIXME: Make structs for these.
constexpr int offsetof_fps_current_frame = 0; // offsetof(fps_t, current_frame)
constexpr int offsetof_frame_prev = -16; // offsetof(frame_t, prev)
constexpr int offsetof_frame_next = -8; // offsetof(frame_t, next)

static constexpr MCPhysReg PSPReg = X86::R15;

// NHM-FIXME: This must be implemented somewhere.
// NHM-FIXME: use llvm::alignTo
template <typename T>
T align_up(T value, T   align) {
  return ((value + align - 1) / align) * align;
}

class X86FunctionPrivateStacks final : public TargetFunctionPrivateStacks {
public:
  static char ID;

  X86FunctionPrivateStacks() : TargetFunctionPrivateStacks(ID, X86::R15) {
    initializeX86FunctionPrivateStacksPass(*PassRegistry::getPassRegistry());
  }

private:
  const TargetMachine *TM; // NHM-FIXME: Remove?

  bool hasBasePointer(const MachineFunction &MF) const override {
    return static_cast<const X86RegisterInfo *>(TRI)->hasBasePointer(MF);
  }

  bool checkFrameIndex(const MachineOperand &MO) const override;

  // NHM-FIXME: No longer need pointer to member.
  void getPointerToFPSData(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, const DebugLoc &Loc, const GlobalVariable *Member, Register Reg);

  // NOTE: Permits PtrReg == ValReg.
  void loadPrivateStackPointer(MachineBasicBlock &MBB,
                               MachineBasicBlock::iterator MBBI, Register Reg,
                               const DebugLoc &Loc = DebugLoc());
  void loadPrivateStackPointerFull(MachineBasicBlock &MBB,
                                   MachineBasicBlock::iterator MBBI,
                                   Register Reg,
                                   const DebugLoc &Loc);
  void loadPrivateStackPointerLeaf(MachineBasicBlock &MBB,
                                   MachineBasicBlock::iterator MBBI,
                                   Register Reg, const DebugLoc &Loc);
  const TargetRegisterClass *computeAddrBaseRegClass(ArrayRef<const MachineOperand *> Uses) override;


  // NOTE: Does not permit PtrReg == ValReg.
  void storePrivateStackPointer(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Reg, const DebugLoc &Loc = DebugLoc());

  bool instrumentSetjmps(MachineFunction &MF) override;

  void partialRedundancyElimination(
      MachineFunction &MF, ArrayRef<MachineInstr *> Uses,
      ArrayRef<MachineInstr *> Kills,
      SmallVectorImpl<std::pair<MachineBasicBlock *,
                                MachineBasicBlock::iterator>> &InsertPts);

  void assignRegsForPrivateStackPointer(MachineFunction &MF, ArrayRef<MachineInstr *> Uses, const DenseMap<int, uint64_t>& PrivateFrameInfo) override;
  void emitPrologue(MachineFunction &MF, unsigned PrivateFrameSize) override;
  void emitEpilogue(MachineFunction &MF, unsigned PrivateFrameSize) override;
};

static MCPhysReg getFreeReg(const LivePhysRegs &LPR, const MachineRegisterInfo &MRI, const TargetRegisterClass &RC = X86::GR64RegClass, ArrayRef<MCPhysReg> IgnoreRegs = {}) {
  for (MCPhysReg Reg : RC) {
    if (LPR.available(MRI, Reg) && !is_contained(IgnoreRegs, Reg)) {
      return Reg;
    }
  }
  return X86::NoRegister;
}

void X86FunctionPrivateStacks::emitPrologue(MachineFunction &MF, unsigned PrivateFrameSize) {
  assert(PrivateFrameSize > 0);
  assert(MF.getFunction().fpsKind() == Function::FullFPS);

  MachineBasicBlock &EntryMBB = MF.front();

  // Claim a scratch register for use in checking whether we've reached the end
  // of the FPS linked list of stack frames.
  LivePhysRegs LPR(*TRI);
  LPR.addLiveIns(EntryMBB);
  MCPhysReg ScratchReg = getFreeReg(LPR, *MRI);
  if (ScratchReg == X86::NoRegister)
    report_fatal_error("Failed to get free scratch register for FPS prologue!");

  // Make sure EFLAGS isn't live-in to the function, as we will clobber it.
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
  NewEntryMBB.addSuccessor(&CheckMBB);

  // NHM-TODO: Propagate to uses and eliminate this array.
  std::array<MCPhysReg, 2> Regs = {ScratchReg, PSPReg};

  // CheckMBB:
  //  fps_t *r0 <- get fps pointer
  //  frame_t *r1 = r0->current_frame;
  //  frame_t *r1 = r1->next;
  //  if (r1 == r1->next) {
  //    __fps_morestack(index);
  //    goto CheckMBB;
  //  }
  //  r0->current_frame = r1;
  //  r1 = r1->data;
  // NHM-FIXME: Can optimize out the r1->data by simply placing the data *before* the frame_t struct (like TLS storage)!
  

  // fps_t *r0 = ...;
  getPointerToFPSData(CheckMBB, CheckMBB.end(), Loc, ThdStacksSym, Regs[0]);

  // frame_t *r1 = r0->current_frame;
  BuildMI(CheckMBB, CheckMBB.end(), Loc, TII->get(X86::MOV64rm), Regs[1])
      .addReg(Regs[0])
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(offsetof_fps_current_frame)
      .addReg(X86::NoRegister);

  // bool overflow = (r1 == r1->next);
  BuildMI(CheckMBB, CheckMBB.end(), Loc, TII->get(X86::CMP64rm))
      .addReg(Regs[1])
      .addReg(Regs[1])
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(offsetof_frame_next)
      .addReg(X86::NoRegister);

  // r1 = r1->next;
  BuildMI(CheckMBB, CheckMBB.end(), Loc, TII->get(X86::MOV64rm), Regs[1])
      .addReg(Regs[1])
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(offsetof_frame_next)
      .addReg(X86::NoRegister);

  // r0->current_frame = r1;
  BuildMI(CheckMBB, CheckMBB.end(), Loc, TII->get(X86::MOV64mr))
      .addReg(Regs[0])
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(offsetof_fps_current_frame)
      .addReg(X86::NoRegister)
      .addReg(Regs[1]);

  // NHM-FIXME: Rename AllocMBB to 'morestack'.
  // if (overflow) goto AllocMBB;
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
      .addExternalSymbol("__fps_morestack")
      .addRegMask(RegMask)
      .addUse(X86::RDI, RegState::ImplicitKill);
  MFI->setAdjustsStack(true);
  MFI->setHasCalls(true);

  const auto AllocPreMBBI = AllocMBB.begin();
  for (auto &LI : AllocMBB.liveins()) {
    const auto Reg = LI.PhysReg;
    const auto *RC = TRI->getMinimalPhysRegClass(Reg);
    int FI = MFI->CreateSpillStackObject(TRI->getSpillSize(*RC), TRI->getSpillAlign(*RC));
    TII->storeRegToStackSlot(AllocMBB, AllocPreMBBI, Reg, /*isKill*/true, FI, RC, /*VReg*/X86::NoRegister);
    TII->loadRegFromStackSlot(AllocMBB, AllocMBB.end(), Reg, FI, RC, /*VReg*/X86::NoRegister);
  }
  TII->insertUnconditionalBranch(AllocMBB, &CheckMBB, DebugLoc());  
  AllocMBB.addSuccessor(&CheckMBB);
}

void X86FunctionPrivateStacks::emitEpilogue(MachineFunction &MF, unsigned PrivateFrameSize) {
  assert(PrivateFrameSize > 0);
  assert(MF.getFunction().fpsKind() == Function::FullFPS);

  DebugLoc Loc;

  for (MachineBasicBlock &MBB : MF) {
    if (MBB.empty() || !MBB.back().isReturn())
      continue;

    auto MBBI = MBB.back().getIterator();

    LivePhysRegs LPR(*TRI);
    LPR.addLiveOuts(MBB);
    LPR.stepBackward(MBB.back());
    assert(!LPR.contains(X86::EFLAGS));
    MCPhysReg ScratchReg = getFreeReg(LPR, *MRI);
    if (ScratchReg == X86::NoRegister)
      report_fatal_error("Failed to get scratach register for FPS epilogue!");
    std::array<MCPhysReg, 2> Regs = {ScratchReg, PSPReg};

    // fps_t *r0 = ...;
    // frame_t *r1 = r0->current_frame;
    // r1 = r1->prev;
    // r0->current_frame = r1;
    getPointerToFPSData(MBB, MBBI, DebugLoc(), ThdStacksSym, Regs[0]);
    BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), Regs[1])
        .addReg(Regs[1])
        .addImm(1)
        .addReg(X86::NoRegister)
        .addImm(offsetof_frame_prev)
        .addReg(X86::NoRegister);
    BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::MOV64mr))
        .addReg(Regs[0])
        .addImm(1)
        .addReg(X86::NoRegister)
        .addImm(offsetof_fps_current_frame)
        .addReg(X86::NoRegister)
        .addReg(Regs[1]);
  }
}

static bool shouldReloadPSP(const MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI) {
  const MachineFunction &MF = *MBB.getParent();
  // Entry block? Needed for LeafFPS (no prologue); FullFPS prologue handles it.
  if (MF.getFunction().fpsKind() != Function::FullFPS &&
      &MBB == &MF.front() && MBBI == MBB.begin())
    return true;
  // Is EH pad?
  if (MBB.isEHPad() && MBBI == MBB.begin())
    return true;
  // Is post-call?
  if (MBBI != MBB.begin() && std::prev(MBBI)->isCall() && !std::prev(MBBI)->isReturn())
    return true;

  return false;
}

void X86FunctionPrivateStacks::assignRegsForPrivateStackPointer(
    MachineFunction &MF, ArrayRef<MachineInstr *> Uses,
    const DenseMap<int, uint64_t> &PrivateFrameInfo) {

  const auto isUse = [&](MachineInstr *MI) { return is_contained(Uses, MI); };

  // Load stack pointer.
  // Insertion points:
  // - Post-calls
  // - Function entrypoint
  // - Exception blocks
  for (MachineBasicBlock &MBB : MF) {
    for (auto MBBI = MBB.begin();; ++MBBI) {
      if (shouldReloadPSP(MBB, MBBI)) {
        loadPrivateStackPointer(MBB, MBBI, PSPReg);
      }
      if (MBBI == MBB.end())
        break;
    }
  }

  // Fixup uses with PSP reg.
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      if (!isUse(&MI))
        continue;
      const int MemRefIdx = X86::getFirstAddrOperandIdx(MI);
      assert(MemRefIdx >= 0);
      MachineOperand &BaseMO = MI.getOperand(MemRefIdx + X86::AddrBaseReg);
      MachineOperand &DispMO = MI.getOperand(MemRefIdx + X86::AddrDisp);
      assert(BaseMO.isFI());
      assert(DispMO.isImm());
      int FI = BaseMO.getIndex();
      BaseMO.ChangeToRegister(PSPReg, /*isDef*/ false);
      assert(PrivateFrameInfo.contains(FI));
      DispMO.setImm(DispMO.getImm() + PrivateFrameInfo.lookup(FI));
    }
  }
}

void X86FunctionPrivateStacks::loadPrivateStackPointerLeaf(
    MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Reg,
    const DebugLoc &Loc) {

  // Emit PSP reload code.
  // MOV r1, [rip+gottpoff(__fps_stackframe_<fn>@gottpoff)]
  // ADD r1, fs:[0] <-- This works because fs:[0] == fs.
  // In effect, it does LEA r1, fs:[r1] (if doing do didn't actually ignore FS entirely).
  BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), Reg)
      .addReg(X86::RIP)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addGlobalAddress(FPSSym, 0, X86II::MO_GOTTPOFF)
      .addReg(X86::NoRegister);
  BuildMI(MBB, MBBI, Loc, TII->get(X86::ADD64rm), Reg)
      .addReg(Reg)
      .addReg(X86::NoRegister)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(0)
      .addReg(X86::FS);
}

void X86FunctionPrivateStacks::loadPrivateStackPointerFull(
    MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Reg,
    const DebugLoc &Loc) {

  getPointerToFPSData(MBB, MBBI, DebugLoc(), ThdStacksSym, Reg);
  BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::MOV64rm), Reg)
      .addReg(Reg)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(0)
      .addReg(X86::NoRegister);
}

void X86FunctionPrivateStacks::loadPrivateStackPointer(
    MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Reg,
    const DebugLoc &Loc) {
  const MachineFunction &MF = *MBB.getParent();
  const Function &F = MF.getFunction();

  // NHM-TODO: Make this an EXPENSIVE_CHECKS?
#ifndef NDEBUG
  LivePhysRegs LPR(*TRI);
  LPR.addLiveOuts(MBB);
  for (MachineInstr &MI : reverse(MBB)) {
    LPR.stepBackward(MI);
    if (MI.getIterator() == MBBI)
      break;
  }
  assert(LPR.available(*MRI, Reg) || MRI->isReserved(Reg));
  const bool LiveEFLAGS = LPR.contains(X86::EFLAGS);
  assert(!LiveEFLAGS && "Expected no live EFLAGS under new approach!");
#endif

  // Normal case: no live EFLAGS.
  switch (F.fpsKind()) {
  case Function::FullFPS:
    loadPrivateStackPointerFull(MBB, MBBI, Reg, Loc);
    break;
  case Function::LeafFPS:
    loadPrivateStackPointerLeaf(MBB, MBBI, Reg, Loc);
    break;
  default:
    report_fatal_error("unhandled FPS type");
  }
}

void X86FunctionPrivateStacks::getPointerToFPSData(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, const DebugLoc &Loc, const GlobalVariable *Member, Register Reg) {
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
        TII->storeRegToStackSlot(MBB, MBBI, Reg, /*isKill*/true, FI, RC, /*VReg*/X86::NoRegister);
      }
    }
    TII->loadRegFromStackSlot(MBB, MBBI, X86::RDI, CtxFI, &X86::GR64RegClass, /*VReg*/X86::NoRegister);
    BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::CALLpcrel32))
        .addExternalSymbol("__fps_ctx_pop")
        .addRegMask(RegMask)
        .addUse(X86::RDI, RegState::ImplicitKill);
    for (const auto &[Reg, FI] : FIs) {
      TII->loadRegFromStackSlot(MBB, MBBI, Reg, FI, TRI->getMinimalPhysRegClass(Reg), /*VReg*/X86::NoRegister);
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
    TII->loadRegFromStackSlot(*Setjmp->getParent(), Setjmp->getIterator(), X86::RDI, CtxFI, &X86::GR64RegClass, /*VReg*/X86::NoRegister);
    BuildMI(*Setjmp->getParent(), Setjmp->getIterator(), Loc, TII->get(X86::CALL64pcrel32))
        .addExternalSymbol("__fps_ctx_push")
        .addRegMask(RegMask)
        .addUse(X86::RDI, RegState::ImplicitKill)
        .addDef(X86::RAX, RegState::Implicit);
    TII->storeRegToStackSlot(*Setjmp->getParent(), Setjmp->getIterator(), X86::RAX, /*isKill*/true, CtxFI, &X86::GR64RegClass, /*VReg*/X86::NoRegister);

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

const TargetRegisterClass *X86FunctionPrivateStacks::computeAddrBaseRegClass(
    ArrayRef<const MachineOperand *> Uses) {
  const TargetRegisterClass *RC = &X86::GR64RegClass;
  for (const MachineOperand *MO : Uses) {
    const MachineInstr &MI = *MO->getParent();
    const TargetRegisterClass *ThisRC = MI.getRegClassConstraint(
        X86::getFirstAddrOperandIdx(MI), TII, TRI);
    if (ThisRC->hasSuperClass(RC)) {
      RC = ThisRC;
    } else if (ThisRC->hasSubClassEq(RC)) {
      // Skip.
    } else {
      report_fatal_error("Expected RC with sub/superset containment!");
    }
  }
  return RC;
}

bool X86FunctionPrivateStacks::checkFrameIndex(const MachineOperand &MO) const {
  const int MemRefBeginIdx = X86::getFirstAddrOperandIdx(*MO.getParent());
  return MemRefBeginIdx >= 0 && MO.getOperandNo() == static_cast<unsigned>(MemRefBeginIdx + X86::AddrBaseReg);
}

} // end namespace

INITIALIZE_PASS(X86FunctionPrivateStacks, PASS_KEY, "X86 Function Private Stacks", false, false)

FunctionPass *llvm::createX86FunctionPrivateStacksPass() {
  return new X86FunctionPrivateStacks();
}

char X86FunctionPrivateStacks::ID = 0;
