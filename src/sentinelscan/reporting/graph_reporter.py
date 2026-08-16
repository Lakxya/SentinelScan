"""Reporters rendering ArchitectureGraph instances into terminal text ASCII trees and structured JSON."""

import json

from sentinelscan.models.graph import ArchitectureGraph, NodeType


class TerminalGraphReporter:
    """Reporter producing a terminal-friendly ASCII tree representation of an ArchitectureGraph."""

    def render(self, graph: ArchitectureGraph, target_path_str: str = ".") -> str:
        lines: list[str] = []
        lines.append("=" * 50)
        lines.append("        SentinelScan Architecture Graph           ")
        lines.append("=" * 50)
        lines.append("")
        lines.append("TARGET DISCOVERY")
        lines.append(f"  Path              : {target_path_str}")
        lines.append(f"  Total Nodes       : {len(graph.nodes)}")
        lines.append(f"  Total Edges       : {len(graph.edges)}")
        lines.append("")
        lines.append("ARCHITECTURE GRAPH TREES")
        lines.append("-" * 50)

        # Build adjacency mapping
        adj: dict[str, list[tuple[str, str]]] = {n_id: [] for n_id in graph.nodes}
        incoming: set[str] = set()

        for edge in graph.edges:
            if edge.source_id in adj:
                adj[edge.source_id].append((edge.target_id, edge.edge_type.value))
                incoming.add(edge.target_id)

        # Identify root nodes (nodes with 0 incoming edges or non-finding top-level resources)
        root_nodes = [
            n for n_id, n in graph.nodes.items()
            if n_id not in incoming and n.node_type != NodeType.SECURITY_FINDING
        ]

        if not root_nodes:
            root_nodes = list(graph.nodes.values())

        if not root_nodes:
            lines.append("  (No architecture nodes discovered)")
        else:
            for root in root_nodes:
                lines.append(f"[{root.id}] ({root.name})")
                children = adj.get(root.id, [])
                for i, (child_id, edge_type) in enumerate(children):
                    is_last = (i == len(children) - 1)
                    prefix = "  └── " if is_last else "  ├── "
                    child_node = graph.nodes.get(child_id)
                    child_label = child_node.name if child_node else child_id
                    lines.append(f"{prefix}[{edge_type}] ---> [{child_id}] ({child_label})")

                    # Print grandchildren (e.g. findings attached to child)
                    grand_children = adj.get(child_id, [])
                    for j, (gc_id, gc_edge_type) in enumerate(grand_children):
                        gc_is_last = (j == len(grand_children) - 1)
                        gc_prefix = "        └── " if gc_is_last else "        ├── "
                        gc_node = graph.nodes.get(gc_id)
                        gc_label = gc_node.name if gc_node else gc_id
                        lines.append(f"{gc_prefix}[{gc_edge_type}] ---> [{gc_id}] ({gc_label})")

                lines.append("")

        lines.append("-" * 50)
        lines.append("EXECUTION COMPLETED.")
        lines.append("=" * 50)
        return "\n".join(lines)


class JsonGraphReporter:
    """Reporter producing structured machine-readable JSON representation of an ArchitectureGraph."""

    def render(self, graph: ArchitectureGraph) -> str:
        return json.dumps(graph.to_dict(), indent=2)
