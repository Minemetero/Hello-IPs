import networkx as nx
import matplotlib.pyplot as plt
from networkx.algorithms import community as nx_community
from pathlib import Path



def visualize_topology(graph):
    """Display the network topology using matplotlib."""
    if graph is None or len(graph.nodes) == 0:
        print("No topology data available")
        return

    pos = nx.spring_layout(graph)
    plt.figure(figsize=(8, 6))
    nx.draw_networkx(
        graph,
        pos=pos,
        with_labels=True,
        node_color="skyblue",
        edge_color="gray",
        node_size=700,
        font_size=8,
    )
    plt.title("Network Topology")
    plt.axis("off")
    plt.show()


def get_node_degrees(graph):
    """Return a mapping of node to its degree."""
    if graph is None:
        return {}
    return dict(graph.degree())


def get_betweenness_centrality(graph):
    """Return betweenness centrality for each node."""
    if graph is None:
        return {}
    return nx.betweenness_centrality(graph)


def detect_communities(graph):
    """Detect communities using a greedy modularity algorithm."""
    if graph is None or graph.number_of_nodes() == 0:
        return []
    communities = nx_community.greedy_modularity_communities(graph)
    return [list(c) for c in communities]


def export_graph(graph, file_path, fmt="graphml"):
    """Export the network graph to GraphML or DOT format."""
    if graph is None or graph.number_of_nodes() == 0:
        raise ValueError("Graph is empty")

    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fmt = fmt.lower()
    if fmt == "graphml":
        nx.write_graphml(graph, path)
    elif fmt == "dot":
        try:
            from networkx.drawing.nx_pydot import write_dot
        except Exception as e:  # pragma: no cover - pydot may not be installed
            raise RuntimeError("DOT export requires pydot") from e
        write_dot(graph, path)
    else:
        raise ValueError(f"Unsupported format: {fmt}")



