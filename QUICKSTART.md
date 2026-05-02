# NIDS Lab 6 - Quick Start Guide

## ⚡ 5-Minute Setup

### 1️⃣ Download Dataset
- Get CIC-IDS2017 from: https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset/
- Extract all 8 CSV files → `data/` folder

### 2️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 3️⃣ Run Pipeline
```bash
python ids_main.py
```

### 4️⃣ Check Results
- `eda_analysis.png` - Data visualization
- `model_comparison.png` - Model performance
- `confusion_matrix_*.png` - Per-model results
- `logs/alerts.log` - Real-time alerts
- `models/best_model_rf.pkl` - Saved model

---

## 📋 Step-by-Step Breakdown

### **PHASE 1: DATA EXPLORATION** (Steps 1-3)
```
Step 1 → Load 8 CSV files
Step 2 → Clean data (missing values, duplicates, optimize memory)
Step 3 → EDA (plot distributions, correlations)
```
⏱️ Time: 5-10 minutes | Output: 3 PNG files + cleaned DataFrame

### **PHASE 2: DATA PREPARATION** (Steps 4-5)
```
Step 4 → Select 18 best features
Step 5 → Scale, encode labels, balance classes (SMOTE)
```
⏱️ Time: 3-5 minutes | Output: Balanced training data

### **PHASE 3: MODEL IMPLEMENTATION** (Steps 6-9)
```
Step 6 → Train 5 models (LR, SVM, NB, KNN, RF)
Step 7 → Evaluate each model (metrics, confusion matrices)
Step 8 → Compare and select best (Random Forest)
Step 9 → Save best model + artifacts
```
⏱️ Time: 5-15 minutes | Output: 5 trained models + comparison chart

### **PHASE 4: DEPLOYMENT** (Step 10)
```
Step 10 → Real-time alert generation on test data
```
⏱️ Time: 1 minute | Output: `alerts.log` with detected threats

---

## 🎯 Key Technical Points

### Feature Selection (18 Features)
```python
[
    'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Mean', 'Bwd Pkt Len Mean',
    'Flow Byts/s', 'Flow Pkts/s', 'Pkt Len Mean', 'Pkt Len Std',
    'SYN Flag Cnt', 'ACK Flag Cnt', 'FIN Flag Cnt', 'RST Flag Cnt',
    'PSH Flag Cnt', 'URG Flag Cnt'
]
```

### Class Balancing (SMOTE + UnderSampling)
```
Original: 654,601 Benign | 1,387 Attacks (470:1 ratio)
         ↓
SMOTE:   654,601 benign | 65,460 attacks (10% of benign)
         ↓
Under:   327,300 benign | 163,650 attacks (2:1 ratio)
```

### Model Rankings (Typical Results)
```
1. 🥇 Random Forest     → F1: 0.95 (BEST)
2. 🥈 KNN              → F1: 0.94
3. 🥉 SVM              → F1: 0.93
4.    Logistic Reg     → F1: 0.89
5.    Naive Bayes      → F1: 0.81
```

---

## ⚠️ Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| "No CSV files found" | Download dataset to `data/` folder |
| Memory error | Dataset is large (~2GB uncompressed), needs ≥8GB RAM |
| Column name not found | Check CSV headers, may differ by source |
| SMOTE import error | Run `pip install imbalanced-learn` |
| Model takes too long | Reduce test set size or use CPU version |

---

## 🔍 Model Selection Criteria

For **Cybersecurity application**, prioritize:
1. **Recall (most important)**: Must catch real attacks
2. **F1-Score**: Balance between precision and recall
3. **Speed**: Needs <10ms inference for real-time
4. **Interpretability**: Important for SOC analysts

✅ **Random Forest** wins on all criteria!

---

## 📊 Expected Output Structure

```
logs/
└── alerts.log          ← Real-time threat detections

models/
├── best_model_rf.pkl   ← Trained Random Forest
├── label_encoder.pkl   ← Attack type encoder
└── scaler.pkl          ← Feature normalizer

eda_analysis.png        ← Distribution + correlation matrix
model_comparison.png    ← Bar charts of model metrics
confusion_matrix_*.png  ← 5 confusion matrices
```

---

## 🎓 What You'll Learn

✓ **Data Science**: Data cleaning, scaling, imbalance handling  
✓ **ML Engineering**: Model training, evaluation, comparison  
✓ **MLOps**: Model serialization, real-time inference  
✓ **Cybersecurity**: IDS concepts, alert generation  
✓ **Git Workflow**: Professional version control practices  

---

## ✨ Advanced Tweaks

### 1. Try Different SMOTE Ratio
```python
# In prepare_data_for_modeling():
SMOTE(sampling_strategy=0.2)  # was 0.1 (more minority samples)
```

### 2. Enable Class Weights in RF
```python
# In train_models():
RandomForestClassifier(
    n_estimators=200,
    class_weight='balanced'  # ← NEW
)
```

### 3. Cross-Validation for Stability
```python
from sklearn.model_selection import cross_val_score
cv_scores = cross_val_score(model, X_train, y_train, cv=5)
```

---

## 🚀 Deployment to Production

Once model is saved:
```python
# Load in production
import joblib
model = joblib.load('models/best_model_rf.pkl')
scaler = joblib.load('models/scaler.pkl')
encoder = joblib.load('models/label_encoder.pkl')

# Predict
new_flow = [[...18 features...]]
new_flow_scaled = scaler.transform(new_flow)
prediction = model.predict(new_flow_scaled)
threat_type = encoder.inverse_transform(prediction)[0]
```

---

## 📚 Git Commit Timeline

```bash
# After setup
git commit -m "init: Initial project scaffold"

# After Step 1-2  
git commit -m "feat: Data loading and preprocessing pipeline"

# After Step 3
git commit -m "feat: EDA with visualizations"

# After Step 4-5
git commit -m "feat: Feature selection and class balancing"

# After Step 6-8
git commit -m "feat: Train and evaluate 5 ML models"

# After Step 9-10
git commit -m "feat: Deploy Random Forest with alerts"
```

---

## ✅ Submission Checklist

- [ ] GitHub repo created (public)
- [ ] All commits timestamped
- [ ] Code runs without errors
- [ ] 5 models trained (confusion matrices visible)
- [ ] README.md complete
- [ ] Model saved as PKL file
- [ ] alerts.log generated
- [ ] requirements.txt updated

---

**Start here → Download data → Run `python ids_main.py` → Done! 🎉**
