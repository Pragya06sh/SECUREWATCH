import torch
import torch.nn.functional as F

from torch_geometric.nn import GCNConv

class GNNModel(torch.nn.Module):

    def __init__(self):

        super(GNNModel, self).__init__()

        self.conv1 = GCNConv(2, 16)
        self.conv2 = GCNConv(16, 32)
        self.conv3 = GCNConv(32, 2)

    def forward(self, x, edge_index):

        x = self.conv1(x, edge_index)
        x = F.relu(x)

        x = self.conv2(x, edge_index)
        x = F.relu(x)

        x = self.conv3(x, edge_index)

        return F.log_softmax(x, dim=1)