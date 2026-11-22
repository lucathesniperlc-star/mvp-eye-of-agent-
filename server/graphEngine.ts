import type {
  ExposureTraversalResult,
  GraphEdge,
  GraphNode,
} from './types';

const SENSITIVE_LEVELS = new Set(['pii', 'phi', 'pci', 'restricted']);

/**
 * Traverses the tenant-scoped security graph from AI agents to sensitive Data objects / Data sources.
 * Strictly filters every node and edge by tenantId so cross-tenant traversal is impossible.
 */
export function findSensitiveExposurePaths(
  allNodes: GraphNode[],
  allEdges: GraphEdge[],
  tenantId: string,
  agentIdFilter?: string
): ExposureTraversalResult[] {
  const tenantNodes = allNodes.filter((n) => n.tenantId === tenantId);
  const tenantEdges = allEdges.filter((e) => e.tenantId === tenantId);

  const nodeMap = new Map<string, GraphNode>();
  for (const node of tenantNodes) {
    nodeMap.set(node.id, node);
  }

  const adj = new Map<string, GraphEdge[]>();
  for (const edge of tenantEdges) {
    if (!nodeMap.has(edge.sourceId) || !nodeMap.has(edge.targetId)) {
      continue;
    }
    const list = adj.get(edge.sourceId) ?? [];
    list.push(edge);
    adj.set(edge.sourceId, list);
  }

  const agentNodes = tenantNodes.filter(
    (n) => n.type === 'AI agent' && (!agentIdFilter || n.id === agentIdFilter)
  );

  const results: ExposureTraversalResult[] = [];

  for (const agentNode of agentNodes) {
    interface WalkState {
      currentId: string;
      steps: ExposureTraversalResult['steps'];
      visited: Set<string>;
    }

    const queue: WalkState[] = [
      {
        currentId: agentNode.id,
        steps: [
          {
            nodeId: agentNode.id,
            nodeType: agentNode.type,
            label: agentNode.label,
            sensitivity: agentNode.sensitivity,
          },
        ],
        visited: new Set([agentNode.id]),
      },
    ];

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (current.steps.length > 8) continue;

      const node = nodeMap.get(current.currentId);
      if (!node) continue;

      if (
        (node.type === 'Data object' || node.type === 'Data source') &&
        node.sensitivity &&
        SENSITIVE_LEVELS.has(node.sensitivity) &&
        current.steps.length >= 2
      ) {
        const riskLevel =
          node.sensitivity === 'pii' || node.sensitivity === 'restricted'
            ? agentNode.riskLevel ?? 'critical'
            : 'high';

        results.push({
          pathId: `path_${agentNode.id}_${node.id}_${current.steps.length}`,
          tenantId,
          agentId: agentNode.id,
          agentLabel: agentNode.label,
          targetDataId: node.id,
          targetDataLabel: node.label,
          targetSensitivity: node.sensitivity,
          hopCount: current.steps.length - 1,
          riskLevel,
          steps: current.steps,
        });
        // Continue looking for deeper Data objects if current is Data source -> CONTAINS -> Data object
      }

      const outgoing = adj.get(current.currentId) ?? [];
      for (const edge of outgoing) {
        if (current.visited.has(edge.targetId)) continue;
        const targetNode = nodeMap.get(edge.targetId);
        if (!targetNode) continue;

        const nextVisited = new Set(current.visited);
        nextVisited.add(targetNode.id);

        queue.push({
          currentId: targetNode.id,
          visited: nextVisited,
          steps: [
            ...current.steps,
            {
              nodeId: targetNode.id,
              nodeType: targetNode.type,
              label: targetNode.label,
              sensitivity: targetNode.sensitivity,
              edgeFromPrev: edge.type,
            },
          ],
        });
      }
    }
  }

  // Prefer deepest concrete Data object paths first
  return results.sort((a, b) => b.hopCount - a.hopCount);
}
