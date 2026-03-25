#include "X86MinimumDirectedMulticut.h"
#include "X86.h"
#include "X86InstrInfo.h"
#include <cassert>

#define DEBUG_TYPE "x86-minimum-directed-multicut"

namespace llvm::X86 {

MinimumDirectedMulticut::MinimumDirectedMulticut(
    MachineFunction& MF, std::unique_ptr<MachineGadgetGraph> Graph):
    MF(MF), Graph(std::move(Graph)), STI(&MF.getSubtarget<X86Subtarget>()),
    TII(STI->getInstrInfo()), TRI(STI->getRegisterInfo()) {}


bool MinimumDirectedMulticut::isFence(const MachineInstr *MI) const {
  return MI && (MI->getOpcode() == X86::LFENCE ||
                (STI->useLVIControlFlowIntegrity() && MI->isCall()));  
}

int MinimumDirectedMulticut::run() {
  assert(Graph && "Can only run multicut once!");
  return hardenLoadsWithHeuristic();
}

int MinimumDirectedMulticut::hardenLoadsWithHeuristic() {
  // If `MF` does not have any fences, then no gadgets would have been
  // mitigated at this point.
  if (Graph->NumFences > 0) {
    LLVM_DEBUG(dbgs() << "Eliminating mitigated paths...\n");
    trimMitigatedEdges();
    LLVM_DEBUG(dbgs() << "Eliminating mitigated paths... Done\n");
  }

  if (Graph->NumGadgets == 0)
    return 0;

  LLVM_DEBUG(dbgs() << "Cutting edges...\n");
  EdgeSet CutEdges{*Graph};

  // Begin by collecting all ingress CFG edges for each node
  DenseMap<const Node *, SmallVector<const Edge *, 2>> IngressEdgeMap;
  for (const Edge &E : Graph->edges())
    if (MachineGadgetGraph::isCFGEdge(E))
      IngressEdgeMap[E.getDest()].push_back(&E);

  // For each gadget edge, make cuts that guarantee the gadget will be
  // mitigated. A computationally efficient way to achieve this is to either:
  // (a) cut all egress CFG edges from the gadget source, or
  // (b) cut all ingress CFG edges to the gadget sink.
  //
  // Moreover, the algorithm tries not to make a cut into a loop by preferring
  // to make a (b)-type cut if the gadget source resides at a greater loop depth
  // than the gadget sink, or an (a)-type cut otherwise.
  for (const Node &N : Graph->nodes()) {
    for (const Edge &E : N.edges()) {
      if (!MachineGadgetGraph::isGadgetEdge(E))
        continue;

      SmallVector<const Edge *, 2> EgressEdges;
      SmallVector<const Edge *, 2> &IngressEdges = IngressEdgeMap[E.getDest()];
      for (const Edge &EgressEdge : N.edges())
        if (MachineGadgetGraph::isCFGEdge(EgressEdge))
          EgressEdges.push_back(&EgressEdge);

      int EgressCutCost = 0, IngressCutCost = 0;
      for (const Edge *EgressEdge : EgressEdges)
        if (!CutEdges.contains(*EgressEdge))
          EgressCutCost += EgressEdge->getValue();
      for (const Edge *IngressEdge : IngressEdges)
        if (!CutEdges.contains(*IngressEdge))
          IngressCutCost += IngressEdge->getValue();

      auto &EdgesToCut =
          IngressCutCost < EgressCutCost ? IngressEdges : EgressEdges;
      for (const Edge *E : EdgesToCut)
        CutEdges.insert(*E);
    }
  }
  LLVM_DEBUG(dbgs() << "Cutting edges... Done\n");
  LLVM_DEBUG(dbgs() << "Cut " << CutEdges.count() << " edges\n");

  LLVM_DEBUG(dbgs() << "Inserting LFENCEs...\n");
  int FencesInserted = insertFences(CutEdges);
  LLVM_DEBUG(dbgs() << "Inserting LFENCEs... Done\n");
  LLVM_DEBUG(dbgs() << "Inserted " << FencesInserted << " fences\n");

  return FencesInserted;
}

void MinimumDirectedMulticut::trimMitigatedEdges() {
  NodeSet ElimNodes{*Graph};
  EdgeSet ElimEdges{*Graph};
  int RemainingGadgets =
      elimMitigatedEdgesAndNodes(ElimEdges, ElimNodes);
  if (ElimEdges.empty() && ElimNodes.empty()) {
    Graph->NumFences = 0;
    Graph->NumGadgets = RemainingGadgets;
  } else {
    Graph = GraphBuilder::trim(*Graph, ElimNodes, ElimEdges, 0 /* NumFences */,
                               RemainingGadgets);
  }
}

int MinimumDirectedMulticut::elimMitigatedEdgesAndNodes(
    EdgeSet &ElimEdges /* in, out */,
    NodeSet &ElimNodes /* in, out */) const {
  auto& G = *Graph; // FIXME: replace
  if (G.NumFences > 0) {
    // Eliminate fences and CFG edges that ingress and egress the fence, as
    // they are trivially mitigated.
    for (const Edge &E : G.edges()) {
      const Node *Dest = E.getDest();
      if (isFence(Dest->getValue())) {
        ElimNodes.insert(*Dest);
        ElimEdges.insert(E);
        for (const Edge &DE : Dest->edges())
          ElimEdges.insert(DE);
      }
    }
  }

  // Find and eliminate gadget edges that have been mitigated.
  int RemainingGadgets = 0;
  NodeSet ReachableNodes{G};
  for (const Node &RootN : G.nodes()) {
    if (llvm::none_of(RootN.edges(), MachineGadgetGraph::isGadgetEdge))
      continue; // skip this node if it isn't a gadget source

    // Find all of the nodes that are CFG-reachable from RootN using DFS
    ReachableNodes.clear();
    std::function<void(const Node *, bool)> FindReachableNodes =
        [&](const Node *N, bool FirstNode) {
          if (!FirstNode)
            ReachableNodes.insert(*N);
          for (const Edge &E : N->edges()) {
            const Node *Dest = E.getDest();
            if (MachineGadgetGraph::isCFGEdge(E) && !ElimEdges.contains(E) &&
                !ReachableNodes.contains(*Dest))
              FindReachableNodes(Dest, false);
          }
        };
    FindReachableNodes(&RootN, true);

    // Any gadget whose sink is unreachable has been mitigated
    for (const Edge &E : RootN.edges()) {
      if (MachineGadgetGraph::isGadgetEdge(E)) {
        if (ReachableNodes.contains(*E.getDest())) {
          // This gadget's sink is reachable
          ++RemainingGadgets;
        } else { // This gadget's sink is unreachable, and therefore mitigated
          ElimEdges.insert(E);
        }
      }
    }
  }
  return RemainingGadgets;
}

int MinimumDirectedMulticut::insertFences(EdgeSet &CutEdges /* in, out */) const
{
  auto& G = *Graph; // FIXME
  int FencesInserted = 0;
  for (const Node &N : G.nodes()) {
    for (const Edge &E : N.edges()) {
      if (CutEdges.contains(E)) {
        MachineInstr *MI = N.getValue(), *Prev;
        MachineBasicBlock *MBB;                  // Insert an LFENCE in this MBB
        MachineBasicBlock::iterator InsertionPt; // ...at this point
        if (MI == MachineGadgetGraph::ArgNodeSentinel) {
          // insert LFENCE at beginning of entry block
          MBB = &MF.front();
          InsertionPt = MBB->begin();
          Prev = nullptr;
        } else if (MI->isBranch()) { // insert the LFENCE before the branch
          MBB = MI->getParent();
          InsertionPt = MI;
          Prev = MI->getPrevNode();
          // Remove all egress CFG edges from this branch because the inserted
          // LFENCE prevents gadgets from crossing the branch.
          for (const Edge &E : N.edges()) {
            if (MachineGadgetGraph::isCFGEdge(E))
              CutEdges.insert(E);
          }
        } else { // insert the LFENCE after the instruction
          MBB = MI->getParent();
          InsertionPt = MI->getNextNode() ? MI->getNextNode() : MBB->end();
          Prev = InsertionPt == MBB->end()
                     ? (MBB->empty() ? nullptr : &MBB->back())
                     : InsertionPt->getPrevNode();
        }
        // Ensure this insertion is not redundant (two LFENCEs in sequence).
        if ((InsertionPt == MBB->end() || !isFence(&*InsertionPt)) &&
            (!Prev || !isFence(Prev))) {
          BuildMI(*MBB, InsertionPt, DebugLoc(), TII->get(X86::LFENCE));
          ++FencesInserted;
        }
      }
    }
  }
  return FencesInserted;
}


}
