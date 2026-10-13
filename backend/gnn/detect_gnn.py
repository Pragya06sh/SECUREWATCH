import torch

from gnn_model import GNNModel


model = GNNModel()

model.load_state_dict(
    torch.load("gnn_model.pth")
)

model.eval()


def detect_gnn_attack(requests, rssi):

    x = torch.tensor([
        [requests, rssi],
        [requests, rssi]
    ], dtype=torch.float)

    edge_index = torch.tensor([
        [0, 1],
        [1, 0]
    ], dtype=torch.long)

    with torch.no_grad():

        output = model(x, edge_index)

        pred = output.argmax(dim=1)

    if pred[0] == 1:
        return True

    return False