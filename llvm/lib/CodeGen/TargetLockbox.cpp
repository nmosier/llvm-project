#include "llvm/CodeGen/TargetLockbox.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/Support/DebugLog.h"
#include <utility>

#define DEBUG_TYPE "target-lockbox"

using namespace llvm;

static void sanityCheckDSOLocal(const Function &F) {
  // Sanity check: dso_local should be a superset?
  assert(!F.isImplicitDSOLocal() || F.isDSOLocal());

}

static bool mayLowerToIndirectCall(const MachineInstr &MI) {
  assert(MI.isCall());
  const MachineOperand &MO = MI.getOperand(0);
  if (MO.isReg())
    return true;
  if (!MO.isGlobal()) {
    LDBG() << "unhandled call operand type: " << MO;
    return true;
  }
  assert(MO.isGlobal());
  const auto *G = dyn_cast<Function>(MO.getGlobal());
  if (!G)
    return true;
  // Sanity check: dso_local should be a superset?
  sanityCheckDSOLocal(*G);
  if (G->isDSOLocal())
    return false;
  // Conservative fallback.
  return true;
}

static bool isIndirectControl(const MachineInstr &MI) {
  if (MI.isCall())
    return mayLowerToIndirectCall(MI);

  if (MI.isReturn())
    return true;

  if (MI.isIndirectBranch())
    return true;
  
  return false;
}

static bool mustCalleeHaveLockboxAttr(const MachineInstr &MI) {
  assert(MI.isCall());
  const MachineOperand &MO = MI.getOperand(0);

  // If the call is indirect, then the callee might not need access,
  // since we can't view its definition.
  // NHM-TODO: Could add an explicit attribute to function pointers
  // to get better performance. That way we could look into the attribute
  // of the called operand.
  if (MO.isReg())
    return false;
  if (!MO.isGlobal()) {
    LDBG() << "unhandled call operand type: " << MO;
    return false;
  }

  // The call is direct.
  assert(MO.isGlobal());
  const Function *G = dyn_cast<Function>(MO.getGlobal());
  if (!G)
    return false;

  // If the callee doesn't have the Lockbox attribute,
  // then it doesn't need access.
  if (!G->hasFnAttribute(Attribute::Lockbox))
    return false;

  // If the callee may be pre-empted at runtime, then
  // it may not need access.
  sanityCheckDSOLocal(*G);
  if (!G->isDSOLocal())
    return false;

  // Otherwise, this callee must have access.
  return true;
}

static bool mustCallerHaveLockboxAttr(const MachineFunction &MF) {
  const Function &F = MF.getFunction();
  // If we can't enumerate all callers, conservatively return false.
  if (!F.hasLocalLinkage() || F.hasAddressTaken())
    return false;

  // Otherwise, enumerate all callers.
  for (const User *U : F.users()) {
    if (const Instruction *I = dyn_cast<Instruction>(U)) {
      const Function *G = I->getFunction();
      if (!G->hasFnAttribute(Attribute::Lockbox)) {
        // Found a caller without Lockbox; bailing.
        return false;
      }
    }
  }

  return true;
}

bool TargetLockbox::isDisableAccessPoint(const MachineInstr &MI) const {
  // If indirect control-flow is unsafe, then disable access.
  if (!IsIndirectControlSafe && isIndirectControl(MI))
    return true;

  // If we're calling something that may not have the lockbox attribute.
  if (MI.isCall())
    return !mustCalleeHaveLockboxAttr(MI);

  // If we're returning somewhere that may not have the lockbox attribute.
  if (MI.isReturn())
    return !mustCallerHaveLockboxAttr(*MI.getParent()->getParent());

  return false;
}

void TargetLockbox::identifyDisableAccessPoints(
    MachineFunction &MF, SmallVectorImpl<ProgramPoint> &Out) {

  Function &F = MF.getFunction();
  sanityCheckDSOLocal(F);

  for (MachineBasicBlock &MBB : MF)
    for (MachineInstr &MI : MBB)
      if (isDisableAccessPoint(MI))
        Out.emplace_back(&MBB, MI.getIterator());
}

void TargetLockbox::identifyEnableAccessPoints(
    MachineFunction &MF, SmallVectorImpl<ProgramPoint> &Out) {

  // Add entry block, if this function may be called by a non-lockbox caller.
  if (!mustCallerHaveLockboxAttr(MF)) {
    MachineBasicBlock &Entry = MF.front();
    Out.emplace_back(&Entry, Entry.begin());
  }

  // Add jump targets, if indircet control-flow is unsafe.
  if (const auto *JTI = MF.getJumpTableInfo(); !IsIndirectControlSafe && JTI)
    for (const auto &JTE : JTI->getJumpTables())
      for (auto *MBB : JTE.MBBs)
        Out.emplace_back(MBB, MBB->getFirstNonPHI());

  // Add post-calls.
  for (auto &MBB : MF)
    for (auto &MI : MBB)
      if (MI.isCall() && !MI.isReturn() && (!mustCalleeHaveLockboxAttr(MI) || !IsIndirectControlSafe))
        Out.emplace_back(&MBB, std::next(MI.getIterator()));
}

static constexpr bool Enable = true;
static constexpr bool Disable = false;

void TargetLockbox::optimizeAccesses(MachineBasicBlock &MBB,
                                     AccessPointVecImpl &MBBIs) const {
  AccessPointVec OrderedMBBIs;
  bool SeenMemoryAccess = false;
  for (auto MBBI = MBB.begin();;) {
    const bool IsEnable = llvm::is_contained(MBBIs, AccessPoint(MBBI, Enable));
    const bool IsDisable =
        llvm::is_contained(MBBIs, AccessPoint(MBBI, Disable));
    // Enable semantically precedes disable.
    if (IsEnable) {
      // NOTE: This assertion was rightfully failing if the callee might've
      // been called from multiple places.
      // assert(OrderedMBBIs.empty() || OrderedMBBIs.back().second == Disable);
      SeenMemoryAccess = false;
      OrderedMBBIs.emplace_back(MBBI, Enable);
    }
    if (IsDisable) {
      if (SeenMemoryAccess) {
        OrderedMBBIs.emplace_back(MBBI, Disable);
      } else if (!OrderedMBBIs.empty()) {
        assert(OrderedMBBIs.back().second == Enable);
        LDBG() << "Removing dead enable: " << *OrderedMBBIs.back().first;
        OrderedMBBIs.pop_back();
      }
    }

    if (MBBI == MBB.end())
      break;

    SeenMemoryAccess |= MBBI->mayLoadOrStore();

    ++MBBI;
  }

  MBBIs = std::move(OrderedMBBIs);
}

static void deduplicateAccesses(SmallVector<std::pair<MachineBasicBlock::iterator, bool>> &MBBIs) {
  SmallVector<std::pair<MachineBasicBlock::iterator, bool>> Out;
  for (const auto &p : MBBIs)
    if (!llvm::is_contained(Out, p))
      Out.push_back(p);
  MBBIs = std::move(Out);
}

void TargetLockbox::instrumentFunction(MachineFunction &MF,
                                       ProgramPointVec &EnablePoints,
                                       ProgramPointVec &DisablePoints) {
  // NHM-TODO: Can optimize this with a data-flow analysis.

  // Rekey program points by basic block.
  std::unordered_map<MachineBasicBlock *, AccessPointVec> Map;

  for (auto [MBB, MBBI] : EnablePoints)
    Map[MBB].emplace_back(MBBI, Enable);
  for (auto [MBB, MBBI] : DisablePoints)
    Map[MBB].emplace_back(MBBI, Disable);

  // NHM-FIXME: Extract the filtering.
  for (MachineBasicBlock &MBB : MF) {
    const auto &MBBIs = Map[&MBB];
    AccessPointVec OrderedMBBIs = MBBIs;
    if (shouldOptimizeAccesses()) {
      optimizeAccesses(MBB, OrderedMBBIs);
    } else {
      deduplicateAccesses(OrderedMBBIs);
    }

    // Instrument the block.
    for (auto [MBBI, Access] : OrderedMBBIs) {
      emitAccess(MBB, MBBI, Access == Enable);
      LDBG() << "Emitted access";
    }
  }
}

bool TargetLockbox::runOnMachineFunction(MachineFunction &MF) {
  initialize(MF);

  Function &F = MF.getFunction();
  if (!F.hasFnAttribute(Attribute::Lockbox))
    return false;

  LDBG() << "Processing " << MF.getName();

  SmallVector<ProgramPoint> EnablePoints, DisablePoints;
  identifyEnableAccessPoints(MF, EnablePoints);
  identifyDisableAccessPoints(MF, DisablePoints);

  LDBG() << "Found " << EnablePoints.size() << " enable points and " << DisablePoints.size() << " disable points";

  instrumentFunction(MF, EnablePoints, DisablePoints);

  MF.verify(nullptr, nullptr, &errs());

  return true;
}

// NHM-TODO: Merge these functions with the identical definition in TargetFunctionPrivateStacks.cpp.
static void getLiveRegsAt(const MachineBasicBlock &MBB,
                          MachineBasicBlock::const_iterator MBBI,
                          LivePhysRegs &LPR) {
  LPR.addLiveOuts(MBB);
  for (const MachineInstr &MI : reverse(MBB)) {
    LPR.stepBackward(MI);
    if (MI.getIterator() == MBBI)
      return;
  }
}

MCPhysReg TargetLockbox::getScratchReg(
    const LivePhysRegs &LPR, ArrayRef<MCPhysReg> Blacklist) const {
  for (MCPhysReg Reg : ScratchRC)
    if (LPR.available(*MRI, Reg) && !is_contained(Blacklist, Reg))
      return Reg;
  report_fatal_error("No scratch register found");
}

MCPhysReg TargetLockbox::getScratchReg(
    const MachineBasicBlock &MBB, MachineBasicBlock::const_iterator MBBI,
    ArrayRef<MCPhysReg> Blacklist) const {
  LivePhysRegs LPR(*TRI);
  getLiveRegsAt(MBB, MBBI, LPR);
  return getScratchReg(LPR, Blacklist);
}

void TargetLockbox::initialize(MachineFunction &MF) {
  const auto &STI = MF.getSubtarget();
  TII = STI.getInstrInfo();
  TRI = STI.getRegisterInfo();
  MRI = &MF.getRegInfo();

  Module &M = *MF.getFunction().getParent();
  LLVMContext &Ctx = M.getContext();

  auto *MaskTy = IntegerType::get(Ctx, MaskBitWidth);
  // NHM-TODO: Might be able to mark this as constant?
  // NHM-TODO: If we make both passes pre-regalloc, we could load the mask into
  // a vreg.
  const StringRef MaskEnableName = "__lockbox_mask_enable";
  const StringRef MaskDisableName = "__lockbox_mask_disable";
  auto CreateMaskSym = [&] (StringRef Name) -> GlobalVariable * {
    return new GlobalVariable(M, MaskTy, false, GlobalVariable::ExternalLinkage, nullptr, Name);
  };
  MaskEnableSym = M.getOrInsertGlobal(MaskEnableName, MaskTy, [&] { return CreateMaskSym(MaskEnableName); });
  MaskDisableSym = M.getOrInsertGlobal(MaskDisableName, MaskTy, [&] { return CreateMaskSym(MaskDisableName); });

}