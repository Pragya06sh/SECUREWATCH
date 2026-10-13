import pandas as pd
import numpy as np
import os

np.random.seed(42)

# Create folder
os.makedirs("data", exist_ok=True)

samples = 8000

records = []

for i in range(samples):

    rssi = np.random.randint(-95, -25)

    request_count = np.random.poisson(5)

    connection_duration = np.random.randint(1, 300)

    device_type = np.random.randint(1, 6)

    manufacturer_known = np.random.choice([0,1], p=[0.3,0.7])

    packet_rate = np.random.normal(50, 15)

    anomaly_score = np.random.random()

    # REALISTIC ATTACK CONDITIONS
    attack = 0

    if (
        rssi > -40
        or request_count > 10
        or manufacturer_known == 0
        or packet_rate > 80
        or anomaly_score > 0.85
    ):
        attack = 1

    records.append([
        rssi,
        request_count,
        connection_duration,
        device_type,
        manufacturer_known,
        packet_rate,
        anomaly_score,
        attack
    ])

columns = [
    "rssi",
    "request_count",
    "connection_duration",
    "device_type",
    "manufacturer_known",
    "packet_rate",
    "anomaly_score",
    "attack"
]

df = pd.DataFrame(records, columns=columns)

file_path = "data/bluetooth_realistic_dataset.csv"

df.to_csv(file_path, index=False)

print("\nDataset created successfully")
print("Shape:", df.shape)
print("\nAttack Distribution:")
print(df["attack"].value_counts())