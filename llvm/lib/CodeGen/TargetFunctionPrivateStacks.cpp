#include "llvm/CodeGen/TargetFunctionPrivateStacks.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/CodeGen/FunctionPrivateStacks.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Constants.h"
#include "llvm/CodeGen/LivePhysRegs.h"

#define DEBUG_TYPE "target-fps"

using namespace llvm;

bool TargetFunctionPrivateStacks::runOnMachineFunction(MachineFunction &MF) {
  if (!MF.getFunction().hasFnAttribute(Attribute::FunctionPrivateStack))
    return false;
  assert(!MF.getName().starts_with("__fps_"));

  auto &STI = MF.getSubtarget();
  TII = STI.getInstrInfo();
  TRI = STI.getRegisterInfo();
  MFI = &MF.getFrameInfo();
  MRI = &MF.getRegInfo();
  Function &F = MF.getFunction();
  Module &M = *F.getParent();
  LLVMContext &Ctx = M.getContext();

  // Make sure the private stack pointer register is not used anywhere.
#ifndef NDEBUG
  for (const MachineBasicBlock &MBB : MF)
    for (const MachineInstr &MI : MBB)
      for (const MachineOperand &MO : MI.operands())
        if (MO.isReg())
          assert(MO.getReg() != PSPReg);
#endif

  // Make sure there is no base pointer and no dynamic stack allocations.
  if (EnableFPSStrictMode) {
    assert(!hasBasePointer(MF) &&
           "No function should have a base pointer!");
    assert(!MFI->hasVarSizedObjects() && "All variable-sized stack objects should have been moved to the unsafe stack already!");
  }

  // Populate global FPS variables.
  // NHM-TODO: Probably should just move these to a full-fps-specific area.
  StackIdxSym = cast_or_null<GlobalVariable>(M.getNamedValue(("__fps_stackidx_" + MF.getName()).str()));
  ThdStacksSym =
      cast_or_null<GlobalVariable>(M.getNamedValue("__fps_thd_stacks"));
  FrameSizeSym = cast_or_null<GlobalVariable>(
      M.getNamedValue(("__fps_framesize_" + MF.getName()).str()));
  switch (F.fpsKind()) {
  case Function::FullFPS:
    assert(FrameSizeSym && StackIdxSym && ThdStacksSym);
    break;
  case Function::LeafFPS:
    break;
  default:
    report_fatal_error("unhandled FPS kind");
  }

  // Collect information about the private stack frame.
  DenseMap<int, uint64_t> PrivateFrameInfo;
  SmallVector<MachineInstr *> PrivateFrameAccesses;
  uint64_t PrivateFrameSize =
      collectPrivateFrameObjects(MF, PrivateFrameInfo, PrivateFrameAccesses);

  if (PrivateFrameSize == 0) {
    // NHM-TODO: It turns out we actually didn't to reserve the PSP register.
    // This means that, in theory, we could un-spill some registers.
    return false;
  }

  // LeafFPS: Create the stack frame.
  if (F.fpsKind() == Function::LeafFPS) {
    auto *Int8Ty = IntegerType::get(Ctx, 8);
    auto *ArrTy = ArrayType::get(Int8Ty, PrivateFrameSize);
    auto *ArrVal = Constant::getNullValue(ArrTy);
    FPSSym = new GlobalVariable(
        M, ArrTy, /*isConstant*/ false, GlobalVariable::InternalLinkage, ArrVal,
        "__fps_stackframe_" + F.getName(),
        /*InsertBefore*/ nullptr, GlobalVariable::InitialExecTLSModel);
    // NHM-FIXME: ^ This should be local dynamic TLS model, not initial exec,
    // ideally. Need to figure out how to integrate use of __tls_get_addr().
  }

  // Load private stack pointer throughout function.
  assignRegsForPrivateStackPointer(MF, PrivateFrameAccesses, PrivateFrameInfo);

  // Emit prologue and epilogue for full FPSes.
  if (F.fpsKind() == Function::FullFPS) {
    emitPrologue(MF, PrivateFrameSize);
    emitEpilogue(MF, PrivateFrameSize);
  }

  // Erase unused stack slots.
  for (const auto &[FI, _] : PrivateFrameInfo)
    MFI->RemoveStackObject(FI);

  MF.verify();

  instrumentSetjmps(MF);

  // Update frame size symbol with the correct constant.
  // NHM-FIXME: This should just use FrameSizeSym->getType() rather than recreating the int64 type.
  if (FrameSizeSym) {
    FrameSizeSym->setInitializer(ConstantInt::get(
        IntegerType::get(M.getContext(), 64), PrivateFrameSize));
  }

  return true;
}

uint64_t TargetFunctionPrivateStacks::collectPrivateFrameObjects(
    MachineFunction &MF, DenseMap<int, uint64_t> &PrivateFrameInfo,
    SmallVectorImpl<MachineInstr *> &PrivateFrameAccesses) {
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

    auto CompatibleUse = [&](const MachineOperand *MO) -> bool {
      const MachineInstr &MI = *MO->getParent();
      const TargetRegisterClass *RC =
          MI.getRegClassConstraint(MO->getOperandNo(), TII, TRI);
      return RC->contains(PSPReg);
    };
    if (!llvm::all_of(Uses, CompatibleUse)) {
      LLVM_DEBUG(dbgs() << "skipping frame index " << FI
                        << " since the PSP reg has an incompatible class\n");
      continue;
    }

    Align ObjAlign = MFI->getObjectAlign(FI);
    PrivateFrameAlign = std::max(PrivateFrameAlign, ObjAlign);
    PrivateFrameSize = llvm::alignTo(PrivateFrameSize, ObjAlign);
    PrivateFrameInfo[FI] = PrivateFrameSize;
    assert(MFI->getObjectSize(FI) > 0);
    PrivateFrameSize += MFI->getObjectSize(FI);

    for (MachineOperand *UseOp : Uses) {
      MachineInstr *MI = UseOp->getParent();
      PrivateFrameAccesses.push_back(MI);
    }
  }
  return llvm::alignTo(PrivateFrameSize, PrivateFrameAlign);
}

bool TargetFunctionPrivateStacks::frameIndexOnlyUsedInMemoryOperands(int FI, MachineFunction &MF, SmallVectorImpl<MachineOperand *> &Uses) {
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      for (MachineOperand &MO : MI.operands()) {
        if (!(MO.isFI() && MO.getIndex() == FI))
          continue;
        if (!checkFrameIndex(MO))
          return false;
        Uses.push_back(&MO);
      }
    }
  }
  return true;
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

void TargetFunctionPrivateStacks::assignRegsForPrivateStackPointer(
    MachineFunction &MF, ArrayRef<MachineInstr *> Uses,
    const DenseMap<int, uint64_t> &PrivateFrameInfo) {

  const auto IsUse = [&](MachineInstr *MI) { return is_contained(Uses, MI); };

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
  for (MachineBasicBlock &MBB : MF)
    for (MachineInstr &MI : MBB)
      if (IsUse(&MI))
        fixupPrivateStackAccess(MI, PrivateFrameInfo);
}

const TargetRegisterClass *TargetFunctionPrivateStacks::computeAddrBaseRegClass(
    ArrayRef<const MachineOperand *> Uses) const {
  const TargetRegisterClass *RC = TRI->getMinimalPhysRegClass(PSPReg);
  for (const MachineOperand *MO : Uses) {
    const MachineInstr &MI = *MO->getParent();
    const TargetRegisterClass *ThisRC = MI.getRegClassConstraint(MO->getOperandNo(), TII, TRI);
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

void TargetFunctionPrivateStacks::loadPrivateStackPointer(
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
  const bool LiveEFLAGS = LPR.contains(FlagsReg);
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