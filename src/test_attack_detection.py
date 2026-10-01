import os
import joblib
import pandas as pd

MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')
DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'raw', 'cicids2017_cleaned.csv')

print("Loading saved model and preprocessing tools...")
model = joblib.load(os.path.join(MODEL_DIR, 'random_forest_model.pkl'))
scaler = joblib.load(os.path.join(MODEL_DIR, 'scaler.pkl'))
label_encoder = joblib.load(os.path.join(MODEL_DIR, 'label_encoder.pkl'))
feature_names = joblib.load(os.path.join(MODEL_DIR, 'feature_names.pkl'))

print(f"Reading attack samples from {DATA_PATH}...")
df = pd.read_csv(DATA_PATH)
df.columns = df.columns.str.strip()

# Pick one real sample of every attack type present in the dataset
attack_samples = df.groupby('Attack Type', as_index=False).first()

print("\n" + "=" * 65)
print(f"{'ACTUAL ATTACK TYPE':<22} | {'AI PREDICTION':<22} | STATUS")
print("=" * 65)

for _, row in attack_samples.iterrows():
    ground_truth = row['Attack Type']
    
    # Extract only the 52 training features
    sample_df = pd.DataFrame([row[feature_names]])
    
    # Scale and predict
    scaled_vector = scaler.transform(sample_df)
    scaled_df = pd.DataFrame(scaled_vector, columns=feature_names)
    
    pred_idx = model.predict(scaled_df)[0]
    predicted_label = label_encoder.inverse_transform([pred_idx])[0]
    
    status = "PASS (MATCH)" if ground_truth == predicted_label else "MISMATCH"
    print(f"{ground_truth:<22} | {predicted_label:<22} | {status}")

print("=" * 65)