import torch
import matplotlib.pyplot as plt

from gnn_model import GNNModel
from dataset import generate_dataset


dataset = generate_dataset(300)

model = GNNModel()

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=0.01
)

loss_fn = torch.nn.NLLLoss()

losses = []

print("Training GNN Model...")

for epoch in range(50):

    total_loss = 0

    for data in dataset:

        optimizer.zero_grad()

        out = model(data.x, data.edge_index)

        loss = loss_fn(out, data.y)

        loss.backward()

        optimizer.step()

        total_loss += loss.item()

    avg_loss = total_loss / len(dataset)

    losses.append(avg_loss)

    print(f"Epoch {epoch+1} Loss: {avg_loss:.4f}")

# Save model

torch.save(model.state_dict(),
           "gnn_model.pth")

print("\nModel Saved!")

# Plot Loss

plt.plot(losses)

plt.title("GNN Training Loss")

plt.xlabel("Epoch")

plt.ylabel("Loss")

plt.savefig("plots/gnn_loss.png")

plt.show()