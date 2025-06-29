import networkx as nx
import matplotlib.pyplot as plt


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

