import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
from feature_extractor import EmailFeatureExtractor
import matplotlib.pyplot as plt
import seaborn as sns

def train_model(data_path='dataset/email_dataset.csv', model_save_path='models/phishing_model.pkl'):
    print("Loading dataset...")
    df = pd.read_csv(data_path)
    
    # We expect 'text' and 'label' columns
    if 'text' not in df.columns or 'label' not in df.columns:
        raise ValueError("Dataset must contain 'text' and 'label' columns")
        
    X = df['text']
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Building pipeline...")
    # Best ML Pipeline recommended
    pipeline = Pipeline([
        ('cleaner', EmailFeatureExtractor()),
        ('tfidf', TfidfVectorizer(max_features=5000)),
        ('model', LogisticRegression(random_state=42, class_weight='balanced'))
    ])
    
    print("Training model...")
    pipeline.fit(X_train, y_train)
    
    print("Evaluating model...")
    y_pred = pipeline.predict(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {acc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Save model
    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    joblib.dump(pipeline, model_save_path)
    print(f"Model saved to {model_save_path}")
    
    # Generate Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6, 4))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Safe', 'Phishing'], yticklabels=['Safe', 'Phishing'])
    plt.title('Confusion Matrix')
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    os.makedirs('notebooks', exist_ok=True)
    plt.savefig('notebooks/confusion_matrix.png')
    print("Confusion matrix saved to notebooks/confusion_matrix.png")

if __name__ == "__main__":
    train_model()
