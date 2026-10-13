import torch
import random
from torch_geometric.data import Data

def generate_graph():

    num_nodes = random.randint(5, 15)

    x = []

    labels = []

    for i in range(num_nodes):

        requests = random.randint(1, 10)
        rssi = random.randint(-100, -20)

        x.append([requests, rssi])

        if requests > 6 or rssi < -85:
            labels.append(1)
        else:
            labels.append(0)

    x = torch.tensor(x, dtype=torch.float)

    edge_index = []

    for i in range(num_nodes - 1):
        edge_index.append([i, i+1])
        edge_index.append([i+1, i])

    edge_index = torch.tensor(edge_index).t().contiguous()

    y = torch.tensor(labels, dtype=torch.long)

    return Data(x=x, edge_index=edge_index, y=y)


def generate_dataset(num_graphs=200):

    dataset = []

    for _ in range(num_graphs):
        dataset.append(generate_graph())

    return dataset