#include "MCTargetDesc/X86MCTargetDesc.h"
#include "MCTargetDesc/X86BaseInfo.h"
#include "X86.h"
#include "X86InstrInfo.h"
#include "X86RegisterInfo.h"
#include "X86Subtarget.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/RegAllocPBQP.h"
#include "llvm/CodeGen/RegisterScavenging.h"
#include "llvm/CodeGen/TargetFunctionPrivateStacks.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Support/DebugLog.h"

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
constexpr int offsetof_frame_next = -8;  // offsetof(frame_t, next)
constexpr int offsetof_frame_current_frame_ptr = -24; // offsetof(frame_t, current_frame_ptr)

// NHM-FIXME: This must be implemented somewhere.
// NHM-FIXME: use llvm::alignTo
template <typename T>
T align_up(T value, T   align) {
  return ((value + align - 1) / align) * align;
}

class X86FunctionPrivateStacks final : public TargetFunctionPrivateStacks {
public:
  static char ID;

  X86FunctionPrivateStacks() : TargetFunctionPrivateStacks(ID, X86::R15, X86::EFLAGS, X86::GR64RegClass) {
    initializeX86FunctionPrivateStacksPass(*PassRegistry::getPassRegistry());
  }

private:
  const TargetMachine *TM; // NHM-FIXME: Remove?

  bool hasBasePointer(const MachineFunction &MF) const override {
    return static_cast<const X86RegisterInfo *>(TRI)->hasBasePointer(MF);
  }

  // NHM-FIXME: No longer need pointer to member.
  void getPointerToFPSData(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, const GlobalVariable *Member, MCPhysReg DestReg, MCPhysReg _ = X86::NoRegister) const override;

  void loadPrivateStackPointerLeaf(MachineBasicBlock &MBB,
                                   MachineBasicBlock::iterator MBBI,
                                   Register Reg) override;

  // NOTE: Does not permit PtrReg == ValReg.
  void storePrivateStackPointer(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Reg, const DebugLoc &Loc = DebugLoc());

  bool instrumentSetjmps(MachineFunction &MF) override;

  void emitPrologueCheck(MachineBasicBlock &CheckMBB,
                         std::array<MCPhysReg, 2> Regs,
                         unsigned PrivateFrameSize) override;
  void emitPrologueAlloc(MachineBasicBlock &AllocMBB,
                         std::array<MCPhysReg, 2> Regs,
                         const uint32_t *RegMask) override;
  MachineOperand getCondEqualMO() const override {
    return MachineOperand::CreateImm(X86::COND_E);
  }

  void emitEpilogueImpl(MachineBasicBlock &MBB,
                        MachineBasicBlock::iterator MBBI,
                        std::array<MCPhysReg, 2> Regs) override;

  MachineOperand &getAddrOp(MachineInstr &MI, unsigned OpIdx) const {
    const int MemRefIdx = X86::getFirstAddrOperandIdx(MI);
    assert(MemRefIdx >= 0);
    return MI.getOperand(MemRefIdx + OpIdx);
  }

  void loadRegFromBaseReg(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Dest, Register Src) const override {
    BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), Dest)
        .addReg(Src)
        .addImm(1)
        .addReg(X86::NoRegister)
        .addImm(0)
        .addReg(X86::NoRegister);
  }

  bool needScratchForPointerToFPSData() const override { return false; }

  bool isLockboxInstr(const MachineInstr &MI) const override {
    return X86::isLockboxOpcode(MI.getOpcode());
  }
};

void X86FunctionPrivateStacks::loadPrivateStackPointerLeaf(
    MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, Register Reg) {

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

void X86FunctionPrivateStacks::getPointerToFPSData(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI, const GlobalVariable *Member, MCPhysReg Reg, MCPhysReg _) const {
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

void X86FunctionPrivateStacks::emitPrologueCheck(MachineBasicBlock &CheckMBB,
                                                 std::array<MCPhysReg, 2> Regs,
                                                 unsigned PrivateFrameSize) {
 // fps_t *r0 = ...;
  getPointerToFPSData(CheckMBB, CheckMBB.end(), ThdStacksSym, Regs[0]);

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
}

void X86FunctionPrivateStacks::emitPrologueAlloc(MachineBasicBlock &AllocMBB,
                                                 std::array<MCPhysReg, 2> Regs,
                                                 const uint32_t *RegMask) {
  const Function &F = AllocMBB.getParent()->getFunction();
  const bool Lockbox = F.hasFnAttribute(Attribute::Lockbox);
  // AllocMBB:
  //   __fps_allocstack(__fps_stackidx_<name>);
  //   jmp CheckMBB
  BuildMI(AllocMBB, AllocMBB.end(), DebugLoc(), TII->get(X86::MOV64rm),
          X86::RDI)
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

  if (Lockbox) {
#ifndef NDEBUG
    LivePhysRegs LPR(*TRI);
    LPR.addLiveOuts(AllocMBB);
    for (MCPhysReg Reg : {X86::EAX, X86::EDX, X86::ECX})
      assert(LPR.available(*MRI, Reg));
#endif
    BuildMI(AllocMBB, AllocMBB.end(), Loc, TII->get(X86::LOCKBOX_ENABLE));
    LDBG() << "Added lockbox enable";
  }
}

void X86FunctionPrivateStacks::emitEpilogueImpl(
    MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI,
    std::array<MCPhysReg, 2> Regs) {
  auto [ScratchReg, PSPReg] = Regs;
  const Function &F = MBB.getParent()->getFunction();

  const bool Lockbox = F.hasFnAttribute(Attribute::Lockbox);

#if 0
  if (Lockbox)
    BuildMI(MBB, MBBI, Loc, TII->get(X86::LOCKBOX_ENABLE));
#endif

  // load ScratchReg, [PSPReg - 16]
  BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), ScratchReg)
      .addReg(PSPReg)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(offsetof_frame_prev)
      .addReg(X86::NoRegister);

  // load PSPReg, [PSPReg - 24]
  BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64rm), PSPReg)
      .addReg(PSPReg)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(offsetof_frame_current_frame_ptr)
      .addReg(X86::NoRegister);

  // store ScratchReg, [PSPReg]
  BuildMI(MBB, MBBI, Loc, TII->get(X86::MOV64mr))
      .addReg(PSPReg)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(0)
      .addReg(X86::NoRegister)
      .addReg(ScratchReg);

#if 0
  if (Lockbox)
    BuildMI(MBB, MBBI, Loc, TII->get(X86::LOCKBOX_DISABLE));
#endif
}

} // end namespace

INITIALIZE_PASS(X86FunctionPrivateStacks, PASS_KEY, "X86 Function Private Stacks", false, false)

FunctionPass *llvm::createX86FunctionPrivateStacksPass() {
  return new X86FunctionPrivateStacks();
}

char X86FunctionPrivateStacks::ID = 0;
