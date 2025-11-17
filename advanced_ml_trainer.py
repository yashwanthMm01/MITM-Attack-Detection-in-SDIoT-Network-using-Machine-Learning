#!/usr/bin/env python3
"""
Advanced ML Model Trainer
Trains multiple ML models on real collected dataset
Compares performance and selects best model
"""
import pandas as pd
import numpy as np
import pickle
import json
from datetime import datetime
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (classification_report, confusion_matrix,
                            accuracy_score, precision_score, recall_score,
                            f1_score, roc_auc_score, roc_curve)

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    PLOTTING_AVAILABLE = True
except ImportError:
    PLOTTING_AVAILABLE = False
    print("⚠ matplotlib/seaborn not available. Plotting disabled.")


class AdvancedMLTrainer:
    def __init__(self, dataset_path='collected_dataset.csv'):
        self.dataset_path = dataset_path
        self.df = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.scaler = None
        self.models = {}
        self.best_model = None
        self.best_model_name = None
        self.feature_names = []

    def load_dataset(self):
        """Load and validate dataset"""
        print("="*70)
        print("LOADING DATASET")
        print("="*70)
        
        try:
            self.df = pd.read_csv(self.dataset_path)
            print(f"✓ Loaded dataset from {self.dataset_path}")
        except FileNotFoundError:
            print(f"✗ Dataset not found: {self.dataset_path}")
            print("  Run data_collector.py first to collect training data!")
            return False
        
        print(f"\nDataset shape: {self.df.shape}")
        print(f"  Samples: {len(self.df)}")
        print(f"  Features: {len(self.df.columns) - 3}")  # Exclude timestamp, mac, label
        
        # Check labels
        if 'label' not in self.df.columns:
            print("✗ 'label' column not found!")
            return False
        
        label_counts = self.df['label'].value_counts()
        print(f"\nClass distribution:")
        print(f"  Normal (0): {label_counts.get(0, 0)} samples")
        print(f"  Attack (1): {label_counts.get(1, 0)} samples")
        
        # Check for minimum samples
        if len(self.df) < 50:
            print("\n⚠ Warning: Very small dataset! Collect more data for better results.")
        
        if label_counts.get(0, 0) < 10 or label_counts.get(1, 0) < 10:
            print("✗ Not enough samples for each class (need at least 10 each)")
            return False
        
        return True

    def preprocess_data(self):
        """Preprocess and prepare data"""
        print("\n" + "="*70)
        print("PREPROCESSING DATA")
        print("="*70)
        
        # Remove non-feature columns
        exclude_cols = ['timestamp', 'src_mac', 'label']
        feature_cols = [col for col in self.df.columns if col not in exclude_cols]
        self.feature_names = feature_cols
        
        print(f"\nFeatures ({len(feature_cols)}):")
        for i, col in enumerate(feature_cols, 1):
            print(f"  {i}. {col}")
        
        # Separate features and labels
        X = self.df[feature_cols].values
        y = self.df['label'].values
        
        # Handle missing values
        if np.isnan(X).any():
            print("\n⚠ Found NaN values. Filling with 0...")
            X = np.nan_to_num(X, 0)
        
        # Split data
        test_size = 0.25 if len(self.df) > 100 else 0.30
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        print(f"\nTrain/Test split:")
        print(f"  Training set: {len(self.X_train)} samples")
        print(f"  Testing set: {len(self.X_test)} samples")
        
        # Feature scaling
        self.scaler = StandardScaler()
        self.X_train = self.scaler.fit_transform(self.X_train)
        self.X_test = self.scaler.transform(self.X_test)
        
        print("✓ Features scaled using StandardScaler")
        return True

    def train_random_forest(self):
        """Train Random Forest model"""
        print("\n--- Random Forest Classifier ---")
        
        rf = RandomForestClassifier(
            n_estimators=150,
            max_depth=15,
            min_samples_split=4,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        rf.fit(self.X_train, self.y_train)
        
        train_score = rf.score(self.X_train, self.y_train)
        test_score = rf.score(self.X_test, self.y_test)
        
        print(f"  Training accuracy: {train_score:.4f}")
        print(f"  Testing accuracy: {test_score:.4f}")
        
        self.models['RandomForest'] = rf
        return rf

    def train_gradient_boosting(self):
        """Train Gradient Boosting model"""
        print("\n--- Gradient Boosting Classifier ---")
        
        gb = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            random_state=42
        )
        
        gb.fit(self.X_train, self.y_train)
        
        train_score = gb.score(self.X_train, self.y_train)
        test_score = gb.score(self.X_test, self.y_test)
        
        print(f"  Training accuracy: {train_score:.4f}")
        print(f"  Testing accuracy: {test_score:.4f}")
        
        self.models['GradientBoosting'] = gb
        return gb

    def train_svm(self):
        """Train SVM model"""
        print("\n--- Support Vector Machine ---")
        
        # Use RBF kernel for non-linear classification
        svm = SVC(
            kernel='rbf',
            C=1.0,
            gamma='scale',
            probability=True,  # Enable probability estimates
            random_state=42
        )
        
        svm.fit(self.X_train, self.y_train)
        
        train_score = svm.score(self.X_train, self.y_train)
        test_score = svm.score(self.X_test, self.y_test)
        
        print(f"  Training accuracy: {train_score:.4f}")
        print(f"  Testing accuracy: {test_score:.4f}")
        
        self.models['SVM'] = svm
        return svm

    def train_neural_network(self):
        """Train Neural Network model"""
        print("\n--- Multi-Layer Perceptron (Neural Network) ---")
        
        mlp = MLPClassifier(
            hidden_layer_sizes=(100, 50),
            activation='relu',
            solver='adam',
            max_iter=500,
            random_state=42
        )
        
        mlp.fit(self.X_train, self.y_train)
        
        train_score = mlp.score(self.X_train, self.y_train)
        test_score = mlp.score(self.X_test, self.y_test)
        
        print(f"  Training accuracy: {train_score:.4f}")
        print(f"  Testing accuracy: {test_score:.4f}")
        
        self.models['NeuralNetwork'] = mlp
        return mlp

    def train_all_models(self):
        """Train all ML models"""
        print("\n" + "="*70)
        print("TRAINING MODELS")
        print("="*70)
        
        # Train each model
        self.train_random_forest()
        self.train_gradient_boosting()
        self.train_svm()
        self.train_neural_network()
        
        print("\n✓ All models trained")

    def compare_models(self):
        """Compare all models and select best"""
        print("\n" + "="*70)
        print("MODEL COMPARISON")
        print("="*70)
        
        results = []
        
        for name, model in self.models.items():
            y_pred = model.predict(self.X_test)
            y_prob = model.predict_proba(self.X_test)[:, 1] if hasattr(model, 'predict_proba') else None
            
            metrics = {
                'Model': name,
                'Accuracy': accuracy_score(self.y_test, y_pred),
                'Precision': precision_score(self.y_test, y_pred),
                'Recall': recall_score(self.y_test, y_pred),
                'F1-Score': f1_score(self.y_test, y_pred),
            }
            
            if y_prob is not None:
                metrics['ROC-AUC'] = roc_auc_score(self.y_test, y_prob)
            
            results.append(metrics)
            
            print(f"\n{name}:")
            for metric, value in metrics.items():
                if metric != 'Model':
                    print(f"  {metric}: {value:.4f}")
        
        # Create comparison DataFrame
        df_results = pd.DataFrame(results)
        
        print("\n" + "="*70)
        print("SUMMARY TABLE")
        print("="*70)
        print(df_results.to_string(index=False))
        
        # Select best model (based on F1-score)
        best_idx = df_results['F1-Score'].idxmax()
        self.best_model_name = df_results.loc[best_idx, 'Model']
        self.best_model = self.models[self.best_model_name]
        
        print(f"\n🏆 Best Model: {self.best_model_name}")
        print(f"  F1-Score: {df_results.loc[best_idx, 'F1-Score']:.4f}")
        
        return df_results

    def detailed_evaluation(self):
        """Detailed evaluation of best model"""
        print("\n" + "="*70)
        print(f"DETAILED EVALUATION - {self.best_model_name}")
        print("="*70)
        
        y_pred = self.best_model.predict(self.X_test)
        
        # Classification report
        print("\nClassification Report:")
        print(classification_report(self.y_test, y_pred, 
                                   target_names=['Normal', 'Attack']))
        
        # Confusion matrix
        cm = confusion_matrix(self.y_test, y_pred)
        print("\nConfusion Matrix:")
        print(f"               Predicted")
        print(f"             Normal  Attack")
        print(f"Actual Normal   {cm[0,0]:4d}    {cm[0,1]:4d}")
        print(f"       Attack   {cm[1,0]:4d}    {cm[1,1]:4d}")
        
        # Cross-validation
        if len(self.X_train) > 30:
            cv_scores = cross_val_score(self.best_model, self.X_train, self.y_train, cv=5)
            print(f"\nCross-Validation Scores:")
            print(f"  Mean: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        # Feature importance (if available)
        if hasattr(self.best_model, 'feature_importances_'):
            self.print_feature_importance()
        
        return cm

    def print_feature_importance(self):
        """Print feature importance"""
        importances = self.best_model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        print(f"\nFeature Importance (Top 10):")
        for i in range(min(10, len(indices))):
            idx = indices[i]
            print(f"  {i+1}. {self.feature_names[idx]}: {importances[idx]:.4f}")

    def plot_results(self, df_results, cm):
        """Plot comparison results"""
        if not PLOTTING_AVAILABLE:
            return
        
        try:
            # 1. Model comparison bar chart
            fig, axes = plt.subplots(2, 2, figsize=(15, 10))
            
            # Accuracy comparison
            axes[0, 0].bar(df_results['Model'], df_results['Accuracy'], color='skyblue')
            axes[0, 0].set_title('Model Accuracy Comparison')
            axes[0, 0].set_ylabel('Accuracy')
            axes[0, 0].set_ylim([0, 1])
            axes[0, 0].tick_params(axis='x', rotation=45)
            
            # F1-Score comparison
            axes[0, 1].bar(df_results['Model'], df_results['F1-Score'], color='lightgreen')
            axes[0, 1].set_title('Model F1-Score Comparison')
            axes[0, 1].set_ylabel('F1-Score')
            axes[0, 1].set_ylim([0, 1])
            axes[0, 1].tick_params(axis='x', rotation=45)
            
            # Confusion matrix
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[1, 0],
                       xticklabels=['Normal', 'Attack'],
                       yticklabels=['Normal', 'Attack'])
            axes[1, 0].set_title(f'Confusion Matrix - {self.best_model_name}')
            axes[1, 0].set_ylabel('True Label')
            axes[1, 0].set_xlabel('Predicted Label')
            
            # Feature importance (if available)
            if hasattr(self.best_model, 'feature_importances_'):
                importances = self.best_model.feature_importances_
                indices = np.argsort(importances)[::-1][:10]
                axes[1, 1].barh([self.feature_names[i] for i in indices],
                              importances[indices], color='coral')
                axes[1, 1].set_title('Top 10 Feature Importance')
                axes[1, 1].set_xlabel('Importance')
            else:
                axes[1, 1].text(0.5, 0.5, 'Feature importance\nnot available for this model',
                              ha='center', va='center')
            
            plt.tight_layout()
            plt.savefig('model_evaluation.png', dpi=300, bbox_inches='tight')
            print(f"\n✓ Plots saved to model_evaluation.png")
            
        except Exception as e:
            print(f"⚠ Could not create plots: {e}")

    def save_model(self):
        """Save best model and preprocessing objects"""
        print("\n" + "="*70)
        print("SAVING MODEL")
        print("="*70)
        
        # Save model
        model_file = 'mitm_detector_model.pkl'
        with open(model_file, 'wb') as f:
            pickle.dump(self.best_model, f)
        print(f"✓ Model saved to {model_file}")
        
        # Save scaler
        scaler_file = 'feature_scaler.pkl'
        with open(scaler_file, 'wb') as f:
            pickle.dump(self.scaler, f)
        print(f"✓ Scaler saved to {scaler_file}")
        
        # Save metadata
        metadata = {
            'model_name': self.best_model_name,
            'feature_names': self.feature_names,
            'num_features': len(self.feature_names),
            'training_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'dataset_size': len(self.df),
            'test_accuracy': float(self.best_model.score(self.X_test, self.y_test)),
        }
        
        metadata_file = 'model_metadata.json'
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"✓ Metadata saved to {metadata_file}")
        
        print("\n✓ All files saved successfully!")

    def run_full_training(self):
        """Run complete training pipeline"""
        # Load dataset
        if not self.load_dataset():
            return False
        
        # Preprocess
        if not self.preprocess_data():
            return False
        
        # Train models
        self.train_all_models()
        
        # Compare and select best
        df_results = self.compare_models()
        
        # Detailed evaluation
        cm = self.detailed_evaluation()
        
        # Plot results
        self.plot_results(df_results, cm)
        
        # Save best model
        self.save_model()
        
        print("\n" + "="*70)
        print("✓ TRAINING COMPLETE!")
        print("="*70)
        print(f"\nBest model: {self.best_model_name}")
        print(f"Model file: mitm_detector_model.pkl")
        print(f"Ready to use with production controller!")
        
        return True


def main():
    """Main function"""
    print("="*70)
    print("SDIoT MiTM Detection - Advanced ML Model Trainer")
    print("="*70)
    
    # Get dataset path
    dataset_path = input("\nEnter dataset path (default: collected_dataset.csv): ").strip()
    if not dataset_path:
        dataset_path = 'collected_dataset.csv'
    
    trainer = AdvancedMLTrainer(dataset_path)
    success = trainer.run_full_training()
    
    if not success:
        print("\n✗ Training failed. Check errors above.")
        return 1
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
