import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    ConfusionMatrixDisplay
)

import joblib

# Load dataset

df = pd.read_csv("bluetooth_dataset.csv")

X = df.drop("attack", axis=1)
y = df["attack"]

# Split data

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42
)

# Train model

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10
)

model.fit(X_train, y_train)

# Predict

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("Model Accuracy:", accuracy)

# Save model

joblib.dump(model, "ai_model.pkl")

# ----------------------------------
# CONFUSION MATRIX GRAPH
# ----------------------------------

cm = confusion_matrix(y_test, y_pred)

disp = ConfusionMatrixDisplay(cm)

disp.plot()

plt.title("Confusion Matrix")

plt.savefig("confusion_matrix.png")

plt.close()

# ----------------------------------
# FEATURE IMPORTANCE GRAPH
# ----------------------------------

importance = model.feature_importances_

plt.bar(
    X.columns,
    importance
)

plt.title("Feature Importance")

plt.savefig("feature_importance.png")

plt.close()

print("Training completed")