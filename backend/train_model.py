import pandas as pd
import os
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    ConfusionMatrixDisplay,
    roc_curve,
    auc
)

import joblib

# Load dataset

df = pd.read_csv(
    "data/Train_Test_Network.csv"
)

print("Dataset Loaded")

# Drop missing

df = df.dropna()

# Find label column automatically

label_col = None

for col in df.columns:

    if "label" in col.lower():
        label_col = col

if label_col is None:
    raise Exception("No label column found")

print("Label column:", label_col)

# Convert label

df[label_col] = df[label_col].apply(
    lambda x: 0 if str(x).lower() in ["normal", "benign"] else 1
)

# Select numeric features only

X = df.select_dtypes(include=["number"])

y = df[label_col]

# Remove label from X

X = X.drop(columns=[label_col], errors="ignore")

# Train/Test split

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y

)

# Train model

model = RandomForestClassifier(

    n_estimators=300,
    max_depth=20,
    random_state=42

)

model.fit(X_train, y_train)

# Predict

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\nAccuracy:", accuracy)

# Save model

os.makedirs("models", exist_ok=True)

joblib.dump(

    model,
    "models/rf_model.pkl"

)

# Confusion Matrix

cm = confusion_matrix(y_test, y_pred)

disp = ConfusionMatrixDisplay(cm)

disp.plot()

plt.title("Confusion Matrix")

plt.savefig("confusion_matrix.png")

plt.close()

# ROC Curve

y_prob = model.predict_proba(X_test)[:,1]

fpr, tpr, _ = roc_curve(y_test, y_prob)

roc_auc = auc(fpr, tpr)

plt.plot(fpr, tpr)

plt.title("ROC Curve")

plt.xlabel("FPR")

plt.ylabel("TPR")

plt.savefig("roc_curve.png")

plt.close()

print("\nTraining Completed")