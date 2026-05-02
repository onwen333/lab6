"""
Network Intrusion Detection System (NIDS) using Machine Learning
Author: Student
Date: 2026
Description: Complete ML pipeline for real-time network intrusion detection
"""

import os
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

# Machine Learning Imports
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.metrics import precision_score, recall_score, f1_score

from imblearn.pipeline import Pipeline as ImbPipeline
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler

import joblib
import warnings
import sys
warnings.filterwarnings('ignore')

# Ensure console output handles Unicode safely on Windows
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# ============================================================================
# CONFIGURATION
# ============================================================================

# Select 18 core features as specified in requirements
SELECTED_FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
    'Flow Bytes/s', 'Flow Packets/s', 'Packet Length Mean', 'Packet Length Std',
    'SYN Flag Count', 'ACK Flag Count', 'FIN Flag Count', 'RST Flag Count',
    'PSH Flag Count', 'URG Flag Count'
]

DATA_DIR = Path('data')
MODELS_DIR = Path('models')
LOGS_DIR = Path('logs')

# Create directories if they don't exist
for dir_path in [DATA_DIR, MODELS_DIR, LOGS_DIR]:
    dir_path.mkdir(exist_ok=True)

# ============================================================================
# STEP 1: LOAD AND MERGE DATA
# ============================================================================

def load_and_merge_data():
    """
    Load and merge the 8 CSV files from the CIC-IDS2017 dataset.
    Expected files: Monday, Tuesday, Wednesday, Thursday, Friday
    and attack-specific files (DoS, Infiltration, etc.)
    """
    print("\n" + "="*80)
    print("STEP 1: LOADING AND MERGING DATA")
    print("="*80)
    
    # Get all CSV files in the data directory
    csv_files = sorted(DATA_DIR.glob('*.csv'))
    
    if not csv_files:
        print("⚠️  No CSV files found in the data directory!")
        print(f"   Please place your CIC-IDS2017 CSV files in: {DATA_DIR.absolute()}")
        return None
    
    print(f"\n✓ Found {len(csv_files)} CSV files:")
    for file in csv_files:
        print(f"  - {file.name}")
    
    # Load and concatenate all CSV files
    dfs = []
    for file in csv_files:
        try:
            df = pd.read_csv(file)
            print(f"  Loaded {file.name}: {df.shape[0]} rows, {df.shape[1]} columns")
            dfs.append(df)
        except Exception as e:
            print(f"  ✗ Error loading {file.name}: {e}")
    
    # Merge all dataframes
    merged_df = pd.concat(dfs, ignore_index=True)
    print(f"\n✓ Merged dataset shape: {merged_df.shape}")
    print(f"  Total rows: {merged_df.shape[0]:,}")
    print(f"  Total columns: {merged_df.shape[1]}")
    
    return merged_df


# ============================================================================
# STEP 2: DATA CLEANING AND PREPROCESSING
# ============================================================================

def clean_and_preprocess(df):
    """
    Clean and preprocess the data:
    - Strip whitespace from column names
    - Handle missing and infinite values
    - Drop duplicates and zero-variance features
    - Optimize data types for memory efficiency
    """
    print("\n" + "="*80)
    print("STEP 2: DATA CLEANING AND PREPROCESSING")
    print("="*80)
    
    # Strip whitespace from column names
    df.columns = df.columns.str.strip()
    print(f"\n✓ Cleaned column names")
    
    # Display initial info
    print(f"\nInitial dataset shape: {df.shape}")
    print(f"Initial memory usage: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
    
    # Handle missing values
    missing_count = df.isnull().sum().sum()
    if missing_count > 0:
        print(f"\n✓ Found {missing_count} missing values, replacing with column median")
        for col in df.select_dtypes(include=[np.number]).columns:
            df[col].fillna(df[col].median(), inplace=True)
    
    # Handle infinite values
    inf_mask = np.isinf(df.select_dtypes(include=[np.number])).values.any(axis=1)
    if inf_mask.any():
        print(f"✓ Found {inf_mask.sum()} rows with infinite values, removing them")
        df = df[~inf_mask]
    
    # Drop duplicates
    initial_rows = len(df)
    df.drop_duplicates(inplace=True)
    removed = initial_rows - len(df)
    if removed > 0:
        print(f"✓ Removed {removed} duplicate rows")
    
    # Drop zero-variance features
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    zero_var_cols = [col for col in numeric_cols if df[col].var() == 0]
    if zero_var_cols:
        print(f"✓ Removing {len(zero_var_cols)} zero-variance features: {zero_var_cols}")
        df.drop(columns=zero_var_cols, inplace=True)
    
    # Memory optimization: downcast data types
    print("\n✓ Optimizing data types for memory efficiency:")
    for col in df.select_dtypes(include=['int64']).columns:
        if df[col].max() <= 255:
            df[col] = df[col].astype('uint8')
        elif df[col].max() <= 32767:
            df[col] = df[col].astype('int16')
        else:
            df[col] = df[col].astype('int32')
    
    for col in df.select_dtypes(include=['float64']).columns:
        df[col] = df[col].astype('float32')
    
    final_memory = df.memory_usage(deep=True).sum() / 1024**2
    print(f"  Final memory usage: {final_memory:.2f} MB")
    
    print(f"\n✓ Cleaned dataset shape: {df.shape}")
    
    return df


# ============================================================================
# STEP 3: EXPLORATORY DATA ANALYSIS
# ============================================================================

def exploratory_data_analysis(df):
    """
    Perform EDA:
    - Distribution of attack types
    - Correlation heatmap
    - Basic statistics
    """
    print("\n" + "="*80)
    print("STEP 3: EXPLORATORY DATA ANALYSIS (EDA)")
    print("="*80)
    
    # Find the label column (usually named 'Label')
    label_col = 'Label' if 'Label' in df.columns else df.columns[-1]
    
    print(f"\n✓ Label column: {label_col}")
    print(f"\nAttack Type Distribution:")
    print(df[label_col].value_counts())
    
    # Class imbalance ratio
    class_counts = df[label_col].value_counts()
    print(f"\n✓ Class distribution (%):")
    for idx, (label, count) in enumerate(class_counts.items()):
        percentage = (count / len(df)) * 100
        print(f"  {label}: {percentage:.2f}% ({count:,} samples)")
    
    # Imbalance ratio
    max_class = class_counts.max()
    min_class = class_counts.min()
    imbalance_ratio = max_class / min_class
    print(f"\n⚠️  Imbalance Ratio: {imbalance_ratio:.2f}:1")
    
    # Plot 1: Attack type distribution
    plt.figure(figsize=(12, 5))
    plt.subplot(1, 2, 1)
    df[label_col].value_counts().plot(kind='bar', color='steelblue')
    plt.title('Distribution of Attack Types', fontsize=12, fontweight='bold')
    plt.xlabel('Attack Type')
    plt.ylabel('Count')
    plt.xticks(rotation=45, ha='right')
    
    # Plot 2: Correlation heatmap (first 20 numeric features)
    plt.subplot(1, 2, 2)
    numeric_cols = df.select_dtypes(include=[np.number]).columns[:20]
    corr_matrix = df[numeric_cols].corr()
    sns.heatmap(corr_matrix, cmap='coolwarm', center=0, annot=False, 
                cbar_kws={'label': 'Correlation'})
    plt.title('Feature Correlation Heatmap', fontsize=12, fontweight='bold')
    plt.tight_layout()
    plt.savefig('eda_analysis.png', dpi=300, bbox_inches='tight')
    print(f"\n✓ Saved EDA visualizations to: eda_analysis.png")
    plt.close()


# ============================================================================
# STEP 4: FEATURE SELECTION AND DATA PREPARATION
# ============================================================================

def select_features(df):
    """
    Filter dataset to keep only 18 core features for optimal performance
    and real-time processing speed.
    """
    print("\n" + "="*80)
    print("STEP 4: FEATURE SELECTION")
    print("="*80)
    
    label_col = 'Label' if 'Label' in df.columns else df.columns[-1]
    
    # Check which selected features exist in the dataset
    available_features = [f for f in SELECTED_FEATURES if f in df.columns]
    missing_features = [f for f in SELECTED_FEATURES if f not in df.columns]
    
    print(f"\n✓ Selected {len(available_features)} features:")
    for i, f in enumerate(available_features, 1):
        print(f"  {i:2d}. {f}")
    
    if missing_features:
        print(f"\n⚠️  {len(missing_features)} features not found in dataset:")
        for f in missing_features:
            print(f"  - {f}")
        print("\n💡 Using available features. Verify your dataset column names!")
    
    # Select features
    selected_features = available_features + [label_col]
    df_selected = df[selected_features].copy()
    
    print(f"\n✓ Final dataset shape: {df_selected.shape}")
    
    return df_selected, available_features


# ============================================================================
# STEP 5: PREPARE DATA FOR MODELING
# ============================================================================

def prepare_data_for_modeling(df, feature_list):
    """
    - Encode labels
    - Scale features
    - Handle class imbalance with SMOTE + RandomUnderSampler
    """
    print("\n" + "="*80)
    print("STEP 5: DATA PREPARATION FOR MODELING")
    print("="*80)
    
    label_col = 'Label' if 'Label' in df.columns else df.columns[-1]
    
    # Separate features and labels
    X = df[feature_list].copy()
    y = df[label_col].copy()
    
    # Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    print(f"\n✓ Encoded {len(label_encoder.classes_)} classes:")
    for i, class_name in enumerate(label_encoder.classes_):
        print(f"  {i} → {class_name}")
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    
    print(f"\n✓ Train-test split:")
    print(f"  Training set: {X_train.shape[0]:,} samples")
    print(f"  Test set: {X_test.shape[0]:,} samples")
    
    # Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print(f"✓ Applied StandardScaler")
    
    # Handle class imbalance
    print(f"\n✓ Handling class imbalance with SMOTE + RandomUnderSampler:")
    
    # Build sampling strategy for multi-class data
    class_counts = pd.Series(y_train).value_counts()
    majority_class = class_counts.idxmax()
    target_majority = int(class_counts.max() * 0.5)
    target_minority = int(class_counts.max() * 0.1)
    
    smote_strategy = {
        cls: target_minority
        for cls, count in class_counts.items()
        if cls != majority_class and count < target_minority
    }
    
    if len(smote_strategy) == 0:
        smote_strategy = 'not majority'
    
    smote_k = 1 if class_counts.min() < 6 else 5
    imblearn_pipeline = ImbPipeline([
        ('smote', SMOTE(sampling_strategy=smote_strategy, random_state=42, k_neighbors=smote_k)),
        ('undersample', RandomUnderSampler(sampling_strategy={majority_class: target_majority}, random_state=42))
    ])
    
    X_train_balanced, y_train_balanced = imblearn_pipeline.fit_resample(
        X_train_scaled, y_train
    )
    
    print(f"  Original training samples: {X_train.shape[0]:,}")
    print(f"  Balanced training samples: {X_train_balanced.shape[0]:,}")
    
    # Show balanced class distribution
    unique, counts = np.unique(y_train_balanced, return_counts=True)
    print(f"\n  Balanced class distribution:")
    for class_id, count in zip(unique, counts):
        class_name = label_encoder.inverse_transform([class_id])[0]
        print(f"    {class_name} ({class_id}): {count:,} samples")
    
    # Reduce the balanced training size for faster model training while keeping class balance
    MAX_TRAIN_SAMPLES = 240_000
    if X_train_balanced.shape[0] > MAX_TRAIN_SAMPLES:
        print(f"\n✓ Downsampling balanced training data to {MAX_TRAIN_SAMPLES:,} samples for practical model training")
        rng = np.random.default_rng(42)

        unique_classes = np.unique(y_train_balanced)
        max_per_class = max(1, int(MAX_TRAIN_SAMPLES / len(unique_classes)))
        selected_indices = []

        for cls in unique_classes:
            cls_indices = np.where(y_train_balanced == cls)[0]
            if len(cls_indices) > max_per_class:
                chosen = rng.choice(cls_indices, size=max_per_class, replace=False)
            else:
                chosen = cls_indices
            selected_indices.extend(chosen.tolist())

        selected_indices = np.array(selected_indices, dtype=np.int64)
        perm = rng.permutation(len(selected_indices))
        selected_indices = selected_indices[perm]

        X_train_balanced = X_train_balanced[selected_indices]
        y_train_balanced = y_train_balanced[selected_indices]

        print(f"  Downsampled training samples: {X_train_balanced.shape[0]:,}")
        unique, counts = np.unique(y_train_balanced, return_counts=True)
        print(f"\n  Downsampled class distribution:")
        for class_id, count in zip(unique, counts):
            class_name = label_encoder.inverse_transform([class_id])[0]
            print(f"    {class_name} ({class_id}): {count:,} samples")

    return {
        'X_train': X_train_balanced,
        'X_test': X_test_scaled,
        'y_train': y_train_balanced,
        'y_test': y_test,
        'label_encoder': label_encoder,
        'scaler': scaler
    }


# ============================================================================
# STEP 6: TRAIN MACHINE LEARNING MODELS
# ============================================================================

def train_models(data_dict):
    """
    Train 5 different classification models:
    1. Logistic Regression
    2. Support Vector Machine (SVM)
    3. Naive Bayes
    4. K-Nearest Neighbors
    5. Random Forest
    """
    print("\n" + "="*80)
    print("STEP 6: TRAINING MACHINE LEARNING MODELS")
    print("="*80)
    
    # Check if models already exist
    model_files = [
        MODELS_DIR / 'best_model_random_forest.pkl',
        MODELS_DIR / 'label_encoder.pkl',
        MODELS_DIR / 'scaler.pkl'
    ]
    
    all_models_exist = all(f.exists() for f in model_files)
    
    if all_models_exist:
        print("\n✅ Found existing trained models! Loading from disk...")
        try:
            # Load existing models
            trained_models = {
                'Random Forest': joblib.load(MODELS_DIR / 'best_model_random_forest.pkl')
            }
            label_encoder = joblib.load(MODELS_DIR / 'label_encoder.pkl')
            scaler = joblib.load(MODELS_DIR / 'scaler.pkl')
            
            print("✅ Successfully loaded existing models:")
            print(f"   - Random Forest model: {MODELS_DIR / 'best_model_random_forest.pkl'}")
            print(f"   - Label encoder: {MODELS_DIR / 'label_encoder.pkl'}")
            print(f"   - Feature scaler: {MODELS_DIR / 'scaler.pkl'}")
            
            # Return loaded models and update data_dict
            data_dict['label_encoder'] = label_encoder
            data_dict['scaler'] = scaler
            
            return trained_models
            
        except Exception as e:
            print(f"❌ Error loading existing models: {e}")
            print("   → Will retrain models from scratch...")
    
    # If models don't exist or loading failed, train from scratch
    print("\n🔄 Training models from scratch...")
    
    X_train = data_dict['X_train']
    X_test = data_dict['X_test']
    y_train = data_dict['y_train']
    y_test = data_dict['y_test']
    
    models = {
        'Logistic Regression': LogisticRegression(
            solver='saga',
            max_iter=500,
            n_jobs=-1,
            random_state=42
        ),
        'Support Vector Machine': SVC(kernel='linear', probability=False, random_state=42),
        'Naive Bayes': GaussianNB(),
        'K-Nearest Neighbors': KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    }
    
    trained_models = {}
    
    for model_name, model in models.items():
        print(f"\n🔄 Training {model_name}...")
        model.fit(X_train, y_train)
        trained_models[model_name] = model
        print(f"   ✓ {model_name} training completed")
    
    return trained_models


# ============================================================================
# STEP 7: EVALUATE AND COMPARE MODELS
# ============================================================================

def evaluate_models(trained_models, data_dict):
    """
    Evaluate all models and create comparison report
    """
    print("\n" + "="*80)
    print("STEP 7: MODEL EVALUATION AND COMPARISON")
    print("="*80)
    
    X_test = data_dict['X_test']
    y_test = data_dict['y_test']
    label_encoder = data_dict['label_encoder']
    
    results = {}
    
    for model_name, model in trained_models.items():
        print(f"\n{'='*60}")
        print(f"Model: {model_name}")
        print(f"{'='*60}")
        
        # Predictions
        y_pred = model.predict(X_test)
        
        # Metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        print(f"\nPerformance Metrics:")
        print(f"  Accuracy:  {accuracy:.4f}")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall:    {recall:.4f}")
        print(f"  F1-Score:  {f1:.4f}")
        
        # Classification Report
        print(f"\nDetailed Classification Report:")
        print(classification_report(y_test, y_pred, 
                                   target_names=label_encoder.classes_,
                                   zero_division=0))
        
        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        results[model_name] = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'predictions': y_pred,
            'confusion_matrix': cm
        }
        
        # Plot confusion matrix
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=label_encoder.classes_,
                   yticklabels=label_encoder.classes_)
        plt.title(f'Confusion Matrix - {model_name}', fontsize=12, fontweight='bold')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        plt.savefig(f'confusion_matrix_{model_name.lower().replace(" ", "_")}.png', 
                   dpi=300, bbox_inches='tight')
        plt.close()
    
    return results


# ============================================================================
# STEP 8: MODEL COMPARISON AND SELECTION
# ============================================================================

def compare_and_select_best_model(results):
    """
    Compare all models and identify the best one (Random Forest)
    """
    print("\n" + "="*80)
    print("STEP 8: MODEL COMPARISON AND SELECTION")
    print("="*80)
    
    # Create comparison table
    comparison_df = pd.DataFrame({
        'Model': results.keys(),
        'Accuracy': [results[m]['accuracy'] for m in results.keys()],
        'Precision': [results[m]['precision'] for m in results.keys()],
        'Recall': [results[m]['recall'] for m in results.keys()],
        'F1-Score': [results[m]['f1'] for m in results.keys()]
    })
    
    comparison_df = comparison_df.sort_values('F1-Score', ascending=False)
    
    print("\n📊 Model Comparison Table:")
    print(comparison_df.to_string(index=False))
    
    # Plot comparison
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    
    for idx, metric in enumerate(metrics):
        ax = axes[idx // 2, idx % 2]
        data = comparison_df.sort_values(metric, ascending=True)
        ax.barh(data['Model'], data[metric], color='steelblue')
        ax.set_xlabel(metric)
        ax.set_title(f'{metric} Comparison', fontweight='bold')
        ax.set_xlim(0, 1)
    
    plt.tight_layout()
    plt.savefig('model_comparison.png', dpi=300, bbox_inches='tight')
    print(f"\n✓ Saved comparison chart to: model_comparison.png")
    plt.close()
    
    best_model_name = comparison_df.iloc[0]['Model']
    print(f"\n🏆 BEST MODEL: {best_model_name}")
    print(f"   F1-Score: {comparison_df.iloc[0]['F1-Score']:.4f}")
    
    return best_model_name


# ============================================================================
# STEP 9: SAVE BEST MODEL
# ============================================================================

def save_best_model(best_model_name, trained_models, data_dict):
    """
    Save the best model (Random Forest) for deployment
    """
    print("\n" + "="*80)
    print("STEP 9: SAVING BEST MODEL")
    print("="*80)
    
    best_model = trained_models[best_model_name]
    label_encoder = data_dict['label_encoder']
    scaler = data_dict['scaler']
    
    # Save model
    safe_name = best_model_name.lower().replace(' ', '_')
    model_path = MODELS_DIR / f'best_model_{safe_name}.pkl'
    
    # Check if models already exist
    encoder_path = MODELS_DIR / 'label_encoder.pkl'
    scaler_path = MODELS_DIR / 'scaler.pkl'
    
    if model_path.exists() and encoder_path.exists() and scaler_path.exists():
        print("✅ Models already exist on disk - skipping save operation")
        print(f"   - Model: {model_path}")
        print(f"   - Encoder: {encoder_path}")
        print(f"   - Scaler: {scaler_path}")
    else:
        joblib.dump(best_model, model_path)
        print(f"\n✓ Saved model: {model_path}")
        print(f"  File size: {model_path.stat().st_size / 1024:.2f} KB")
        
        # Save label encoder
        joblib.dump(label_encoder, encoder_path)
        print(f"✓ Saved label encoder: {encoder_path}")
        
        # Save scaler
        joblib.dump(scaler, scaler_path)
        print(f"✓ Saved scaler: {scaler_path}")
    
    return {
        'model': best_model,
        'label_encoder': label_encoder,
        'scaler': scaler,
        'feature_list': SELECTED_FEATURES
    }


# ============================================================================
# STEP 10: REAL-TIME ALERT GENERATION
# ============================================================================

def generate_real_time_alerts(saved_model_dict, data_dict, num_samples=10):
    """
    Simulate real-time network traffic analysis and generate Suricata-style alerts
    """
    print("\n" + "="*80)
    print("STEP 10: REAL-TIME INTRUSION ALERT GENERATION")
    print("="*80)
    
    model = saved_model_dict['model']
    label_encoder = saved_model_dict['label_encoder']
    scaler = saved_model_dict['scaler']
    feature_list = saved_model_dict['feature_list']
    
    X_test = data_dict['X_test']
    y_test = data_dict['y_test']
    
    # Open log file
    log_file = LOGS_DIR / 'alerts.log'
    
    with open(log_file, 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("NETWORK INTRUSION DETECTION SYSTEM - ALERT LOG\n")
        f.write("="*80 + "\n\n")
        
        print(f"\n[ALERT] Generating real-time alerts (first {num_samples} samples):\n")
        
        # Test on first num_samples
        test_samples = X_test[:num_samples]
        test_labels = y_test[:num_samples]
        
        alert_count = 0
        
        for idx, (sample, true_label) in enumerate(zip(test_samples, test_labels)):
            # Make prediction
            prediction = model.predict(sample.reshape(1, -1))[0]
            if hasattr(model, 'predict_proba'):
                confidence = model.predict_proba(sample.reshape(1, -1)).max()
            else:
                confidence = None
            
            # Get class name
            predicted_class = label_encoder.inverse_transform([prediction])[0]
            true_class = label_encoder.inverse_transform([true_label])[0]
            
            # Generate alert if not BENIGN (dataset label uses uppercase)
            if predicted_class.upper() != 'BENIGN':
                alert_count += 1
                confidence_str = f"{confidence:.2%}" if confidence is not None else 'N/A'
                status = 'CORRECT' if predicted_class == true_class else 'INCORRECT'
                alert_msg = (
                    f"[ALERT #{alert_count}] Suspicious traffic detected!\n"
                    f"  Threat Type: {predicted_class}\n"
                    f"  Confidence: {confidence_str}\n"
                    f"  Sample Index: {idx}\n"
                    f"  Ground Truth: {true_class}\n"
                    f"  Status: {status}\n"
                    f"{'-'*70}\n"
                )
                
                print(alert_msg)
                f.write(alert_msg)
        
        # Summary
        summary = (
            f"\n{'='*80}\n"
            f"SUMMARY\n"
            f"{'='*80}\n"
            f"Total Samples Analyzed: {num_samples}\n"
            f"Alerts Generated: {alert_count}\n"
            f"Detection Rate: {(alert_count/num_samples)*100:.1f}%\n"
            f"{'='*80}\n"
        )
        
        print(summary)
        f.write(summary)
    
    print(f"\n✓ Alert log saved to: {log_file}")
    
    return alert_count


# ============================================================================
# MODEL CHECKING UTILITY
# ============================================================================

def check_existing_models():
    """
    Check if trained models already exist and ask user if they want to use them
    """
    model_files = [
        MODELS_DIR / 'best_model_random_forest.pkl',
        MODELS_DIR / 'label_encoder.pkl',
        MODELS_DIR / 'scaler.pkl'
    ]
    
    all_models_exist = all(f.exists() for f in model_files)
    
    if all_models_exist:
        print("\n" + "="*80)
        print("MODEL DETECTION")
        print("="*80)
        print("✅ Found existing trained models in the models/ directory!")
        print("   - best_model_random_forest.pkl")
        print("   - label_encoder.pkl")
        print("   - scaler.pkl")
        print("\n📋 Options:")
        print("   1. Use existing models (skip training) - FAST")
        print("   2. Retrain models from scratch - SLOW")
        
        try:
            choice = input("\nEnter your choice (1 or 2) [default: 1]: ").strip()
            if choice == "2":
                print("🔄 Will retrain models from scratch...")
                return False
            else:
                print("✅ Will use existing models - skipping training!")
                return True
        except:
            print("✅ Using existing models (default)...")
            return True
    
    return False


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """
    Main execution pipeline
    """
    print("\n" + "█"*80)
    print("█" + " "*78 + "█")
    print("█" + " "*15 + "NETWORK INTRUSION DETECTION SYSTEM (NIDS)" + " "*22 + "█")
    print("█" + " "*20 + "Using Machine Learning & Real-time Alerts" + " "*16 + "█")
    print("█" + " "*78 + "█")
    print("█"*80)
    
    # Check for existing models first
    use_existing_models = check_existing_models()
    
    try:
        if use_existing_models:
            # Fast path: Load existing models and generate alerts
            print("\n" + "="*80)
            print("FAST MODE: USING EXISTING MODELS")
            print("="*80)
            
            try:
                # Load models
                model = joblib.load(MODELS_DIR / 'best_model_random_forest.pkl')
                label_encoder = joblib.load(MODELS_DIR / 'label_encoder.pkl')
                scaler = joblib.load(MODELS_DIR / 'scaler.pkl')
                
                print("✅ Successfully loaded existing models!")
                
                # Create minimal data_dict for alert generation
                # We need to load a small sample of data for testing
                df = load_and_merge_data()
                if df is None:
                    return
                
                df_clean = clean_and_preprocess(df)
                df_selected, feature_list = select_features(df_clean)
                data_dict = prepare_data_for_modeling(df_selected, feature_list)
                
                # Override with loaded models
                data_dict['label_encoder'] = label_encoder
                data_dict['scaler'] = scaler
                
                saved_model_dict = {
                    'model': model,
                    'label_encoder': label_encoder,
                    'scaler': scaler,
                    'feature_list': SELECTED_FEATURES
                }
                
                # Generate alerts
                alert_count = generate_real_time_alerts(saved_model_dict, data_dict)
                
            except Exception as e:
                print(f"❌ Error in fast mode: {e}")
                print("   → Switching to full training mode...")
                use_existing_models = False
        
        if not use_existing_models:
            # Full pipeline: load data, process, train, evaluate, save, alert
            # Step 1: Load data
            df = load_and_merge_data()
            if df is None:
                return
            
            # Step 2: Clean and preprocess
            df_clean = clean_and_preprocess(df)
            
            # Step 3: EDA
            exploratory_data_analysis(df_clean)
            
            # Step 4: Feature selection
            df_selected, feature_list = select_features(df_clean)
            
            # Step 5: Prepare data
            data_dict = prepare_data_for_modeling(df_selected, feature_list)
            
            # Step 6: Train models
            trained_models = train_models(data_dict)
            
            # Check if models were loaded from disk (only Random Forest available)
            models_loaded_from_disk = len(trained_models) == 1 and 'Random Forest' in trained_models
            
            if models_loaded_from_disk:
                print("\n" + "="*80)
                print("MODELS LOADED FROM DISK - SKIPPING TRAINING & EVALUATION")
                print("="*80)
                print("✅ Using pre-trained Random Forest model")
                print("   → Skipping model evaluation (already validated)")
                print("   → Proceeding to real-time alert generation...")
                
                # Skip to step 10: Real-time alerts
                saved_model_dict = {
                    'model': trained_models['Random Forest'],
                    'label_encoder': data_dict['label_encoder'],
                    'scaler': data_dict['scaler'],
                    'feature_list': SELECTED_FEATURES
                }
                
                # Step 10: Real-time alert generation
                alert_count = generate_real_time_alerts(saved_model_dict, data_dict)
                
            else:
                # Full pipeline: evaluate, compare, save, and generate alerts
                # Step 7: Evaluate models
                results = evaluate_models(trained_models, data_dict)
                
                # Step 8: Compare and select best
                best_model_name = compare_and_select_best_model(results)
                
                # Step 9: Save best model
                saved_model_dict = save_best_model(best_model_name, trained_models, data_dict)
                
                # Step 10: Real-time alert generation
                alert_count = generate_real_time_alerts(saved_model_dict, data_dict)
        
        print("\n" + "█"*80)
        print("█" + " "*26 + "✓ PIPELINE COMPLETED SUCCESSFULLY" + " "*18 + "█")
        print("█"*80)
        
    except Exception as e:
        print(f"\n❌ Error during execution: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
