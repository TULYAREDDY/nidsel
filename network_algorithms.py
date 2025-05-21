import heapq
from collections import defaultdict, deque
from typing import List, Dict, Set, Tuple, Any
import networkx as nx
import numpy as np

class NetworkAlgorithms:
    """
    A class containing various network analysis algorithms for intrusion detection
    and threat analysis.
    """

    @staticmethod
    def knapsack_alerts(alerts: List[Dict], capacity: int) -> List[Dict]:
        """Prioritize alerts using the Knapsack algorithm"""
        n = len(alerts)
        dp = [[0 for _ in range(capacity + 1)] for _ in range(n + 1)]
        
        # Build table dp[][] in bottom-up manner
        for i in range(1, n + 1):
            for w in range(capacity + 1):
                if alerts[i-1]['complexity'] <= w:
                    dp[i][w] = max(
                        alerts[i-1]['severity'] + dp[i-1][w-alerts[i-1]['complexity']],
                        dp[i-1][w]
                    )
                else:
                    dp[i][w] = dp[i-1][w]
        
        # Find selected alerts
        selected = []
        w = capacity
        for i in range(n, 0, -1):
            if dp[i][w] != dp[i-1][w]:
                selected.append(alerts[i-1])
                w -= alerts[i-1]['complexity']
        
        return selected

    @staticmethod
    def create_network_graph(nodes: List[str], connections: List[Tuple[str, str, float]]) -> nx.Graph:
        """Create a network graph from nodes and connections"""
        G = nx.Graph()
        G.add_nodes_from(nodes)
        G.add_weighted_edges_from(connections)
        return G

    @staticmethod
    def dijkstra_shortest_path(graph: nx.Graph, start: str, end: str) -> Tuple[List[str], float]:
        """Find shortest path using Dijkstra's algorithm"""
        try:
            path = nx.shortest_path(graph, start, end, weight='weight')
            total_risk = sum(graph[path[i]][path[i+1]]['weight'] for i in range(len(path)-1))
            return path, total_risk
        except nx.NetworkXNoPath:
            return [], float('inf')

    @staticmethod
    def dfs_attack_propagation(graph: Dict[str, List[str]], start: str) -> List[str]:
        """Analyze attack propagation using DFS"""
        visited = set()
        path = []
        
        def dfs(node):
            visited.add(node)
            path.append(node)
            for neighbor in graph.get(node, []):
                if neighbor not in visited:
                    dfs(neighbor)
        
        dfs(start)
        return path

    @staticmethod
    def bfs_attack_propagation(graph: Dict[str, List[str]], start: str) -> List[str]:
        """Analyze attack propagation using BFS"""
        visited = set([start])
        queue = [start]
        path = []
        
        while queue:
            node = queue.pop(0)
            path.append(node)
            for neighbor in graph.get(node, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        
        return path

class NetworkAnalyzer:
    def __init__(self):
        self.graph = nx.Graph()
        self.alert_history = []
        self.threat_levels = {
            'low': 0,
            'medium': 1,
            'high': 2
        }

    def analyze_network(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network data and return insights"""
        try:
            # Create or update network graph
            self.graph.clear()
            self.graph.add_nodes_from(n['id'] for n in network_data['nodes'])
            self.graph.add_edges_from(
                (l['source'], l['target'], {'type': l['type']})
                for l in network_data['links']
            )

            # Calculate network metrics
            metrics = {
                'node_count': self.graph.number_of_nodes(),
                'edge_count': self.graph.number_of_edges(),
                'malicious_connections': sum(
                    1 for _, _, data in self.graph.edges(data=True)
                    if data.get('type') == 'malicious'
                ),
                'average_degree': sum(dict(self.graph.degree()).values()) / self.graph.number_of_nodes(),
                'connected_components': nx.number_connected_components(self.graph)
            }

            # Identify potential attack paths
            attack_paths = []
            malicious_nodes = [
                n for n, data in self.graph.nodes(data=True)
                if data.get('type') == 'malicious'
            ]
            target_nodes = [
                n for n, data in self.graph.nodes(data=True)
                if data.get('type') == 'target'
            ]

            for source in malicious_nodes:
                for target in target_nodes:
                    try:
                        path = nx.shortest_path(self.graph, source, target)
                        attack_paths.append({
                            'source': source,
                            'target': target,
                            'path': path,
                            'length': len(path) - 1
                        })
                    except nx.NetworkXNoPath:
                        continue

            # Calculate threat level
            threat_level = self._calculate_threat_level(metrics, attack_paths)

            return {
                'status': 'success',
                'metrics': metrics,
                'attack_paths': attack_paths,
                'threat_level': threat_level,
                'recommendations': self._generate_recommendations(metrics, attack_paths)
            }

        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
            }

    def _calculate_threat_level(self, metrics: Dict[str, Any], attack_paths: List[Dict]) -> str:
        """Calculate overall threat level based on metrics and attack paths"""
        score = 0
        
        # Score based on malicious connections
        score += metrics['malicious_connections'] * 2
        
        # Score based on attack paths
        score += len(attack_paths) * 3
        
        # Score based on network size
        if metrics['node_count'] > 10:
            score += 2
        
        # Determine threat level
        if score > 10:
            return 'high'
        elif score > 5:
            return 'medium'
        return 'low'

    def _generate_recommendations(self, metrics: Dict[str, Any], attack_paths: List[Dict]) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if metrics['malicious_connections'] > 0:
            recommendations.append(
                f"Block {metrics['malicious_connections']} malicious connections"
            )
        
        if attack_paths:
            recommendations.append(
                f"Monitor {len(attack_paths)} potential attack paths"
            )
        
        if metrics['connected_components'] > 1:
            recommendations.append(
                "Consider network segmentation to reduce attack surface"
            )
        
        return recommendations 