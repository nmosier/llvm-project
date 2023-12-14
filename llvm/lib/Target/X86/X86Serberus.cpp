#include "ImmutableGraph.h"
#include "X86.h"
#include "X86Subtarget.h"
#include "X86TargetMachine.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineDominanceFrontier.h"
#include "llvm/CodeGen/MachineDominators.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineLoopInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/RDFGraph.h"
#include "llvm/CodeGen/RDFLiveness.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/DOTGraphTraits.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/DynamicLibrary.h"
#include "llvm/Support/GraphWriter.h"
#include "llvm/Support/raw_ostream.h"
#include "X86MinimumDirectedMulticut.h"

using namespace llvm;
using llvm::X86::MachineGadgetGraph;

// FIXME: Maybe should actually call this "speculative constant-time".
#define PASS_KEY "x86-serberus"
#define DEBUG_TYPE PASS_KEY

static cl::opt<bool> EnableSerberus(
    PASS_KEY, cl::desc("Enable Serberus"), cl::init(false), cl::Hidden);

static cl::opt<bool> NoConditionalBranches(
    PASS_KEY "-no-cbranch",
    cl::desc("Don't treat conditional branches as disclosure gadgets. This "
             "may improve performance, at the cost of security."),
    cl::init(false), cl::Hidden);

// FIXME: Should cross-check configuration with other flags, like no-stack-slot-sharing and
// no-argument-promotion.
static cl::opt<bool> NoSecretArguments(
    PASS_KEY "-no-secargs",
    cl::desc("Disallow secret arguments. This may improve performance, at the "
             "cost of security."),
    cl::init(false), cl::Hidden);


namespace {

class X86SerberusPass : public MachineFunctionPass {
public:
  X86SerberusPass() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override {
    return "X86 Serberus";
  }
  void getAnalysisUsage(AnalysisUsage& AU) const override;
  bool runOnMachineFunction(MachineFunction& MF) override;

  static char ID;
  
private:
  const X86Subtarget *STI = nullptr;
  const TargetInstrInfo *TII = nullptr;
  const TargetRegisterInfo *TRI = nullptr;

  using GraphBuilder = ImmutableGraphBuilder<MachineGadgetGraph>;
  
  std::unique_ptr<MachineGadgetGraph>
  getGadgetGraph(MachineFunction& MF, const MachineLoopInfo& MLI,
                 const MachineDominatorTree& MDT,
                 const MachineDominanceFrontier& MDF) const;

  bool instrUsesRegToAccessMemory(const MachineInstr& MI, unsigned Reg) const;
  bool instrUsesRegToBranch(const MachineInstr& MI, unsigned Reg) const;
  bool instrIsAccess(const MachineInstr& MI) const;
  bool instrIsCAAccess(const MachineInstr& MI) const;
  bool instrIsNCAAccess(const MachineInstr& MI) const;
  bool isFence(const MachineInstr *MI) const {
    return MI && MI->getOpcode() == X86::LFENCE;
  }
};

}

bool X86SerberusPass::instrIsAccess(const MachineInstr& MI) const {
  if (!MI.mayLoadOrStore())
    return false;
  switch (MI.getOpcode()) {
  case X86::MFENCE:
  case X86::SFENCE:
  case X86::LFENCE:
    return false;
  default:
    return true;
  }
}

bool X86SerberusPass::instrUsesRegToAccessMemory(
    const MachineInstr& MI, unsigned Reg) const {
  if (!instrIsAccess(MI))
    return false;

  // FIXME: This does not handle pseudo loading instruction like TCRETURN*
  const MCInstrDesc &Desc = MI.getDesc();
  int MemRefBeginIdx = X86II::getMemoryOperandNo(Desc.TSFlags);
  if (MemRefBeginIdx < 0) {
    LLVM_DEBUG(dbgs() << "Warning: unable to obtain memory operand for loading "
                         "instruction:\n";
               MI.print(dbgs()); dbgs() << '\n';);
    return false;
  }
  MemRefBeginIdx += X86II::getOperandBias(Desc);

  const MachineOperand &BaseMO =
      MI.getOperand(MemRefBeginIdx + X86::AddrBaseReg);
  const MachineOperand &IndexMO =
      MI.getOperand(MemRefBeginIdx + X86::AddrIndexReg);
  return (BaseMO.isReg() && BaseMO.getReg() != X86::NoRegister &&
          TRI->regsOverlap(BaseMO.getReg(), Reg)) ||
         (IndexMO.isReg() && IndexMO.getReg() != X86::NoRegister &&
          TRI->regsOverlap(IndexMO.getReg(), Reg));  
}

bool X86SerberusPass::instrUsesRegToBranch(
    const MachineInstr &MI, unsigned Reg) const {
  if (!MI.isConditionalBranch())
    return false;
  for (const MachineOperand &Use : MI.uses())
    if (Use.isReg() && Use.getReg() == Reg)
      return true;
  return false;
}

bool X86SerberusPass::instrIsCAAccess(const MachineInstr& MI) const {
  if (!instrIsAccess(MI))
    return false;

  const MachineFunction& MF = *MI.getParent()->getParent();
  if (MF.getFrameInfo().hasVarSizedObjects())
    return false;

  auto memop_is_ca = [&] (MachineMemOperand *memop) -> bool {
    if (const Value *V = memop->getValue()) {
      if (const auto *AI = dyn_cast<AllocaInst>(V)) {
        return AI && AI->isStaticAlloca();
      } else if (isa<Constant>(V)) {
        return true;
      } else {
        return false;
      }
    } else if (const PseudoSourceValue *PSV = memop->getPseudoValue()) {
      // Treat all fixed stack accesses (e.g., stack argument load/stores) as NCA accesses.
      return PSV->kind() != PseudoSourceValue::FixedStack;
    } else {
      return false;
    }
  };

  if (MI.memoperands_empty()) {
    LLVM_DEBUG(dbgs() << "warning: access has no machine mem operands: " << MI);
    return false;
  }

  return llvm::all_of(MI.memoperands(), memop_is_ca);
}

bool X86SerberusPass::instrIsNCAAccess(const MachineInstr& MI) const {
  return instrIsAccess(MI) && !instrIsCAAccess(MI);
}


void X86SerberusPass::getAnalysisUsage(AnalysisUsage& AU) const {
  MachineFunctionPass::getAnalysisUsage(AU);
  AU.addRequired<MachineLoopInfo>();
  AU.addRequired<MachineDominatorTree>();
  AU.addRequired<MachineDominanceFrontier>();
  AU.setPreservesCFG();
}

bool X86SerberusPass::runOnMachineFunction(MachineFunction& MF) {
  LLVM_DEBUG(dbgs() << "***** " << getPassName() << " : " << MF.getName()
                    << " *****\n");
  STI = &MF.getSubtarget<X86Subtarget>();
  if (!EnableSerberus)
    return false;

  if (!STI->is64Bit())
    report_fatal_error("Serberus is only supported on 64-bit", false);

  // FIXME: don't skip functions w/ the "optnone" attr...

  TII = STI->getInstrInfo();
  TRI = STI->getRegisterInfo();
  LLVM_DEBUG(dbgs() << "Building gadget graph...\n");
  const auto& MLI = getAnalysis<MachineLoopInfo>();
  const auto& MDT = getAnalysis<MachineDominatorTree>();
  const auto& MDF = getAnalysis<MachineDominanceFrontier>();
  std::unique_ptr<MachineGadgetGraph> Graph = getGadgetGraph(MF, MLI, MDT, MDF);
  LLVM_DEBUG(dbgs() << "Building gadget graph... Done\n");
  if (!Graph)
    return false;

  X86::MinimumDirectedMulticut mincut(MF, std::move(Graph));
  mincut.run();

  return true; // FIXME
}

std::unique_ptr<MachineGadgetGraph>
X86SerberusPass::getGadgetGraph(MachineFunction& MF, const MachineLoopInfo& MLI,
                                const MachineDominatorTree& MDT,
                                const MachineDominanceFrontier& MDF) const {
  using namespace rdf;

  // Build the Register Dataflow Graph using the RDF framework
  DataFlowGraph DFG(MF, *TII, *TRI, MDT, MDF);
  DFG.build();
  Liveness L(MF.getRegInfo(), DFG);
  L.computePhiInfo();

  GraphBuilder Builder;
  using GraphIter = GraphBuilder::BuilderNodeRef;
  DenseMap<MachineInstr *, GraphIter> NodeMap;
  int FenceCount = 0, GadgetCount = 0;
  auto MaybeAddNode = [&NodeMap, &Builder] (MachineInstr *MI) {
    auto Ref = NodeMap.find(MI);
    if (Ref == NodeMap.end()) {
      auto I = Builder.addVertex(MI);
      NodeMap[MI] = I;
      return std::make_pair(I, true);
    } else {
      return std::make_pair(Ref->getSecond(), false);
    }
  };

  // The `Transmitters` map memoizes transmitters found for each def. If a def
  // has not yet been analyzed, then it will not appear in the map. If a def
  // has been analyzed and was determined not to have any transmitters, then
  // its list of transmitters will be empty.
  enum class DepTy {
    Transmitter,
    Data,
    Rf,
  };
  DenseMap<NodeId, std::vector<std::pair<NodeId, DepTy>>> Deps;

  // Analyze all machine instructions to find gadgets and LFENCEs, adding
  // each interesting value to `Nodes`
  auto AnalyzeDef = [&](NodeAddr<DefNode *> SourceDef) {
    SmallSet<NodeId, 8> UsesVisited, DefsVisited;
    std::function<void(NodeAddr<DefNode *>)> AnalyzeDefUseChain =
        [&](NodeAddr<DefNode *> Def) {
          if (Deps.contains(Def.Id))
            return; // Already analyzed `Def`

          // Use RDF to find all the uses of `Def`
          rdf::NodeSet Uses;
          RegisterRef DefReg = Def.Addr->getRegRef(DFG);
          for (auto UseID : L.getAllReachedUses(DefReg, Def)) {
            auto Use = DFG.addr<UseNode *>(UseID);
            if (Use.Addr->getFlags() & NodeAttrs::PhiRef) { // phi node
              NodeAddr<PhiNode *> Phi = Use.Addr->getOwner(DFG);
              for (const auto& I : L.getRealUses(Phi.Id)) {
                if (DFG.getPRI().alias(RegisterRef(I.first), DefReg)) {
                  for (const auto &UA : I.second)
                    Uses.emplace(UA.first);
                }
              }
            } else { // not a phi node
              Uses.emplace(UseID);
            }
          }

          // For each use of `Def`, we want to know whether:
          // (1) The use can leak the Def'ed value,
          // (2) The use can further propagate the Def'ed value to more defs
          for (auto UseID : Uses) {
            if (!UsesVisited.insert(UseID).second)
              continue; // Already visited this use of `Def`

            auto Use = DFG.addr<UseNode *>(UseID);
            assert(!(Use.Addr->getFlags() & NodeAttrs::PhiRef));
            MachineOperand &UseMO = Use.Addr->getOp();
            MachineInstr &UseMI = *UseMO.getParent();
            assert(UseMO.isReg());

            // We naively assume that an instruction propagates any loaded
            // uses to all defs unless the instruction is a call, in which
            // case all arguments will be treated as gadget sources during
            // analysis of the callee function.
            if (UseMI.isCall()) {
              if (NoSecretArguments) {
                Deps[Def.Id].emplace_back(Use.Addr->getOwner(DFG).Id, DepTy::Transmitter);
              } else {
                continue;
              }
            }

            if (UseMI.isReturn() && NoSecretArguments) {
              Deps[Def.Id].emplace_back(Use.Addr->getOwner(DFG).Id, DepTy::Transmitter);
            }

            // Check whether this use can transmit (leak) its value.
            if (instrUsesRegToAccessMemory(UseMI, UseMO.getReg()) ||
                (!NoConditionalBranches &&
                 instrUsesRegToBranch(UseMI, UseMO.getReg()))) {
              Deps[Def.Id].emplace_back(Use.Addr->getOwner(DFG).Id, DepTy::Transmitter);
              if (UseMI.mayLoad())
                continue; // Found a transmitting load -- no need to continue
                          // traversing its defs (i.e., this load will become
                          // a new gadget source anyways).
            }


            // Check whether the use propagates to more defs.
            NodeAddr<InstrNode *> Owner{Use.Addr->getOwner(DFG)};
            rdf::NodeList AnalyzedChildDefs;
            for (const auto &ChildDef :
                     Owner.Addr->members_if(DataFlowGraph::IsDef, DFG)) {
              if (!DefsVisited.insert(ChildDef.Id).second)
                continue; // Already visited this def
              if (Def.Addr->getAttrs() & NodeAttrs::Dead)
                continue;
              if (Def.Id == ChildDef.Id)
                continue; // `Def` uses itself (e.g., increment loop counter)

              AnalyzeDefUseChain(ChildDef);

              // `Def` inherits all of its child defs' transmitters.
              llvm::copy(Deps[ChildDef.Id], std::back_inserter(Deps[Def.Id]));
            }
          }

          // Note that this statement adds `Def.Id` to the map if no
          // dependencies were found for `Def`.
          auto &DefDeps = Deps[Def.Id];

          // Remove duplicate transmitters
          llvm::sort(DefDeps);
          DefDeps.erase(
              std::unique(DefDeps.begin(), DefDeps.end()),
              DefDeps.end());
        };

    // Find all of the transmitters
    AnalyzeDefUseChain(SourceDef);
    SmallVector<NodeId> SourceDefTransmitters;
    for (const auto& [node, depty] : Deps[SourceDef.Id])
      if (depty == DepTy::Transmitter)
        SourceDefTransmitters.push_back(node);
    if (SourceDefTransmitters.empty())
      return; // No transmitters for `SourceDef`

    MachineInstr *Source = SourceDef.Addr->getFlags() & NodeAttrs::PhiRef
                               ? MachineGadgetGraph::ArgNodeSentinel
                               : SourceDef.Addr->getOp().getParent();
    auto GadgetSource = MaybeAddNode(Source);
    // Each transmitter is a sink for `SourceDef`.
    for (auto TransmitterId : SourceDefTransmitters) {
      MachineInstr *Sink = DFG.addr<StmtNode *>(TransmitterId).Addr->getCode();
      auto GadgetSink = MaybeAddNode(Sink);
      // Add the gadget edge to the graph.
      Builder.addEdge(MachineGadgetGraph::GadgetEdgeSentinel,
                      GadgetSource.first, GadgetSink.first);
      ++GadgetCount;
    }
  };

  LLVM_DEBUG(dbgs() << "Analyzing def-use chains to find gadgets\n");
  // Analyze function arguments
  if (!NoSecretArguments) {
    NodeAddr<BlockNode *> EntryBlock = DFG.getFunc().Addr->getEntryBlock(DFG);
    for (NodeAddr<PhiNode *> ArgPhi :
             EntryBlock.Addr->members_if(DataFlowGraph::IsPhi, DFG)) {
      NodeList Defs = ArgPhi.Addr->members_if(DataFlowGraph::IsDef, DFG);
      llvm::for_each(Defs, AnalyzeDef);
    }
  }
  // Analyze every instruction in MF
  for (NodeAddr<BlockNode *> BA : DFG.getFunc().Addr->members(DFG)) {
    for (NodeAddr<StmtNode *> SA :
         BA.Addr->members_if(DataFlowGraph::IsCode<NodeAttrs::Stmt>, DFG)) {
      MachineInstr *MI = SA.Addr->getCode();
      if (isFence(MI)) {
        MaybeAddNode(MI);
        ++FenceCount;
      } else if (MI->mayLoad() && instrIsNCAAccess(*MI)) {
        NodeList Defs = SA.Addr->members_if(DataFlowGraph::IsDef, DFG);
        llvm::for_each(Defs, AnalyzeDef);
      }
    }
  }
  LLVM_DEBUG(dbgs() << "Found " << FenceCount << " fences\n");
  LLVM_DEBUG(dbgs() << "Found " << GadgetCount << " gadgets\n");
  if (GadgetCount == 0)
    return nullptr;
  // NumGadgets += GadgetCount;


  // Traverse CFG to build the rest of the graph
  SmallSet<MachineBasicBlock *, 8> BlocksVisited;
  std::function<void(MachineBasicBlock *, GraphIter, unsigned)> TraverseCFG =
      [&](MachineBasicBlock *MBB, GraphIter GI, unsigned ParentDepth) {
        unsigned LoopDepth = MLI.getLoopDepth(MBB);
        if (!MBB->empty()) {
          // Always add the first instruction in each block
          auto NI = MBB->begin();
          auto BeginBB = MaybeAddNode(&*NI);
          Builder.addEdge(ParentDepth, GI, BeginBB.first);
          if (!BlocksVisited.insert(MBB).second)
            return;

          // Add any instructions within the block that are gadget components
          GI = BeginBB.first;
          while (++NI != MBB->end()) {
            auto Ref = NodeMap.find(&*NI);
            if (Ref != NodeMap.end()) {
              Builder.addEdge(LoopDepth, GI, Ref->getSecond());
              GI = Ref->getSecond();
            }
          }

          // Always add the terminator instruction, if one exists
          auto T = MBB->getFirstTerminator();
          if (T != MBB->end()) {
            auto EndBB = MaybeAddNode(&*T);
            if (EndBB.second)
              Builder.addEdge(LoopDepth, GI, EndBB.first);
            GI = EndBB.first;
          }
        }
        for (MachineBasicBlock *Succ : MBB->successors())
          TraverseCFG(Succ, GI, LoopDepth);
      };
  // ArgNodeSentinel is a pseudo-instruction that represents MF args in the
  // GadgetGraph
  GraphIter ArgNode = MaybeAddNode(MachineGadgetGraph::ArgNodeSentinel).first;
  TraverseCFG(&MF.front(), ArgNode, 0);

  // Add in transient control-flow edges:
  // {returns} -> {post call-sites}
  // {calls} -> {function entrypoints}
  SmallVector<MachineInstr *> EntryInstrs, ExitInstrs;
  for (MachineBasicBlock& MBB : MF) {
    for (MachineInstr& MI : MBB) {
      if (MI.isCall()) {
        ExitInstrs.push_back(&MI);
        if (MachineInstr *PostCallMI = MI.getNextNode())
          EntryInstrs.push_back(PostCallMI);
      } else if (MI.isReturn()) {
        ExitInstrs.push_back(&MI);
      }
    }
  }
  std::function<MachineInstr *(MachineBasicBlock *)> GetFirstInstr = [&] (auto *MBB) {
    assert(MBB);
    if (!MBB->empty())
      return &MBB->front();
    return GetFirstInstr(MBB->getSingleSuccessor());
  };
  EntryInstrs.push_back(GetFirstInstr(&MF.front()));
  for (MachineInstr *EntryMI : EntryInstrs) {
    for (MachineInstr *ExitMI : ExitInstrs) {
      Builder.addEdge(
          std::numeric_limits<MachineGadgetGraph::edge_value_type>::max(),
          MaybeAddNode(ExitMI).first, MaybeAddNode(EntryMI).first);
    }
  }
  
  std::unique_ptr<MachineGadgetGraph> G(Builder.get(FenceCount, GadgetCount));
  LLVM_DEBUG(dbgs() << "Found " << G->nodes_size() << " nodes\n");
  return G;
}

INITIALIZE_PASS_BEGIN(X86SerberusPass, PASS_KEY, "X86 Serberus", false, false)
INITIALIZE_PASS_DEPENDENCY(MachineLoopInfo)
INITIALIZE_PASS_DEPENDENCY(MachineDominatorTree)
INITIALIZE_PASS_DEPENDENCY(MachineDominanceFrontier)
INITIALIZE_PASS_END(X86SerberusPass, PASS_KEY, "X86 Serberus", false, false)

FunctionPass *llvm::createX86SerberusPass() {
  return new X86SerberusPass();
}
                      
char X86SerberusPass::ID = 0;
