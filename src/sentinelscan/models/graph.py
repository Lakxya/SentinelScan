"""Data models for SentinelScan Architecture Graph nodes, edges, and relationship graphs."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class NodeType(str, Enum):
    """Enumeration of supported architecture graph node types."""

    TERRAFORM_RESOURCE = "terraform_resource"
    AWS_IAM_ROLE = "aws_iam_role"
    AWS_IAM_POLICY = "aws_iam_policy"
    AWS_S3_BUCKET = "aws_s3_bucket"
    AWS_KMS_KEY = "aws_kms_key"
    K8S_WORKLOAD = "k8s_workload"
    K8S_SERVICE = "k8s_service"
    K8S_CONFIGMAP = "k8s_configmap"
    K8S_SECRET = "k8s_secret"
    K8S_SERVICE_ACCOUNT = "k8s_service_account"
    DOCKER_IMAGE = "docker_image"
    NETWORK_SERVICE = "network_service"
    SECURITY_FINDING = "security_finding"
    FILE_TARGET = "file_target"


class EdgeType(str, Enum):
    """Enumeration of supported architecture graph relationship edge types."""

    REFERENCES = "REFERENCES"
    ATTACHED_TO = "ATTACHED_TO"
    USES_SECRET = "USES_SECRET"
    USES_CONFIGMAP = "USES_CONFIGMAP"
    USES_SERVICE_ACCOUNT = "USES_SERVICE_ACCOUNT"
    EXPOSES = "EXPOSES"
    EXPOSES_SERVICE = "EXPOSES_SERVICE"
    BUILDS_FROM = "BUILDS_FROM"
    HAS_FINDING = "HAS_FINDING"


@dataclass
class Node:
    """Dataclass representing an identified asset, resource, or finding node in the architecture graph."""

    id: str
    node_type: NodeType
    name: str
    category: str
    file_path: Path | None = None
    start_line: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert Node instance to serializable dictionary."""
        return {
            "id": self.id,
            "node_type": self.node_type.value,
            "name": self.name,
            "category": self.category,
            "file_path": str(self.file_path) if self.file_path else None,
            "start_line": self.start_line,
            "metadata": self.metadata,
        }


@dataclass
class Edge:
    """Dataclass representing a directed relationship edge between two architecture nodes."""

    source_id: str
    target_id: str
    edge_type: EdgeType
    label: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert Edge instance to serializable dictionary."""
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "label": self.label,
            "metadata": self.metadata,
        }


@dataclass
class ArchitectureGraph:
    """Container dataclass representing the complete architecture graph of nodes and edges."""

    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    def add_node(self, node: Node) -> None:
        """Add node to graph, ignoring duplicates based on node ID."""
        if node.id not in self.nodes:
            self.nodes[node.id] = node

    def add_edge(self, edge: Edge) -> None:
        """Add edge to graph, ignoring duplicates based on source, target, and edge_type."""
        for existing in self.edges:
            if (
                existing.source_id == edge.source_id
                and existing.target_id == edge.target_id
                and existing.edge_type == edge.edge_type
            ):
                return
        self.edges.append(edge)

    def to_dict(self) -> dict[str, Any]:
        """Convert ArchitectureGraph instance to serializable dictionary."""
        return {
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "edges": [edge.to_dict() for edge in self.edges],
            "summary": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
            },
        }
