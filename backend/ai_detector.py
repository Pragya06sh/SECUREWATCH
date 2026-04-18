import numpy as np
from sklearn.ensemble import IsolationForest

# Example training data
# [request_count, device_type]
training_data = np.array([
    [1,3],
    [2,3],
    [1,3],
    [3,3],
    [2,3],
    [10,3],
    [12,3],
])

model = IsolationForest(contamination=0.2)
model.fit(training_data)

def detect_attack(request_count, device_type):

    sample = np.array([[request_count, device_type]])

    prediction = model.predict(sample)

    if prediction[0] == -1:
        return True
    else:
        return False