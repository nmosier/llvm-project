#ifndef LLVM_LIB_TARGET_X86_MINIMUMDIRECTEDMULTICUT_H
#define LLVM_LIB_TARGET_X86_MINIMUMDIRECTEDMULTICUT_H

#include "X86Subtarget.h"
#include "ImmutableGraph.h"
#include "llvm/CodeGen/MachineInstr.h"
#include <memory>

namespace llvm::X86 {

struct MachineGadgetGraph : ImmutableGraph<MachineInstr *, int> {
  static constexpr int GadgetEdgeSentinel = -1;
  static constexpr MachineInstr *const ArgNodeSentinel = nullptr;

  using GraphT = ImmutableGraph<MachineInstr *, int>;
  using Node = typename GraphT::Node;
  using Edge = typename GraphT::Edge;
  using size_type = typename GraphT::size_type;
  MachineGadgetGraph(std::unique_ptr<Node[]> Nodes,
                     std::unique_ptr<Edge[]> Edges, size_type NodesSize,
                     size_type EdgesSize, int NumFences = 0, int NumGadgets = 0)
      : GraphT(std::move(Nodes), std::move(Edges), NodesSize, EdgesSize),
        NumFences(NumFences), NumGadgets(NumGadgets) {}
  static inline bool isCFGEdge(const Edge &E) {
    return E.getValue() != GadgetEdgeSentinel;
  }
  static inline bool isGadgetEdge(const Edge &E) {
    return E.getValue() == GadgetEdgeSentinel;
  }
  int NumFences;
  int NumGadgets;
};

class MinimumDirectedMulticut {
public:
  MinimumDirectedMulticut(MachineFunction& MF,
                          std::unique_ptr<MachineGadgetGraph> Graph);
  int run();
private:
  MachineFunction& MF;
  std::unique_ptr<MachineGadgetGraph> Graph;
  const X86Subtarget *STI;
  const TargetInstrInfo *TII;
  const TargetRegisterInfo *TRI;

  using GraphBuilder = ImmutableGraphBuilder<MachineGadgetGraph>;
  using Node = MachineGadgetGraph::Node;
  using Edge = MachineGadgetGraph::Edge;
  using EdgeSet = MachineGadgetGraph::EdgeSet;
  using NodeSet = MachineGadgetGraph::NodeSet;

  int hardenLoadsWithPlugin() const;
  int hardenLoadsWithHeuristic();
  int elimMitigatedEdgesAndNodes(EdgeSet &ElimEdges /* in, out */,
                                 NodeSet &ElimNodes /* in, out */) const;
  void trimMitigatedEdges();
  int insertFences(EdgeSet &CutEdges /* in, out */) const;
  bool instrUsesRegToAccessMemory(const MachineInstr &I, unsigned Reg) const;
  bool instrUsesRegToBranch(const MachineInstr &I, unsigned Reg) const;
  bool isFence(const MachineInstr *MI) const;
};

}

#endif
