import joblib

# Load objects
label_encoder = joblib.load('models/label_encoder.pkl')
model = joblib.load('models/best_model_random_forest.pkl')
scaler = joblib.load('models/scaler.pkl')

# Show label encoder classes
print("LabelEncoder classes:")
for i, cls in enumerate(label_encoder.classes_):
    print(f"{i}: {cls}")

# Show model type and basic info
print("\nModel:")
print(type(model))
print(model)

# Show scaler info
print("\nScaler:")
print(type(scaler))
print("Mean:", scaler.mean_)
print("Scale:", scaler.scale_)

# Show alert log content
print("\nAlert log preview:")
try:
    with open('logs/alerts.log', 'r', encoding='utf-8') as f:
        lines = f.readlines()
        preview = ''.join(lines[:25])
        print(preview)
except FileNotFoundError:
    print('alerts.log not found in logs/')