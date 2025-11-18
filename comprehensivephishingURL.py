import pandas as pd
import numpy as np
import re
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import joblib
import warnings
warnings.filterwarnings('ignore')

class PhishingURLDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            stop_words='english',
            min_df=2,
            max_df=0.8
        )
        self.model = None
        self.label_encoder = LabelEncoder()
        self.feature_names = []
        
    def extract_url_features(self, url):
        """Extract features from URLs"""
        features = {}
        
        # Basic URL features
        features['url_length'] = len(str(url))
        features['num_dots'] = str(url).count('.')
        features['num_hyphens'] = str(url).count('-')
        features['num_underscores'] = str(url).count('_')
        features['num_slashes'] = str(url).count('/')
        features['num_question_marks'] = str(url).count('?')
        features['num_equals'] = str(url).count('=')
        features['num_ampersands'] = str(url).count('&')
        features['num_digits'] = sum(c.isdigit() for c in str(url))
        features['num_letters'] = sum(c.isalpha() for c in str(url))
        
        # Domain features
        domain = str(url).split('/')[0] if '/' in str(url) else str(url)
        features['domain_length'] = len(domain)
        
        # Suspicious patterns
        features['has_ip'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', str(url)) else 0
        features['has_https'] = 1 if 'https' in str(url).lower() else 0
        features['has_http'] = 1 if 'http' in str(url).lower() else 0
        features['has_www'] = 1 if 'www' in str(url).lower() else 0
        
        # Suspicious keywords in URL
        suspicious_keywords = ['login', 'signin', 'verify', 'secure', 'account', 
                             'banking', 'update', 'confirm', 'password', 'click',
                             'phish', 'suspect', 'fraud', 'hack', 'malware']
        features['suspicious_words_count'] = sum(1 for word in suspicious_keywords if word in str(url).lower())
        
        # TLD features
        tlds = ['.com', '.org', '.net', '.edu', '.gov', '.in', '.co.in', 
               '.xyz', '.top', '.shop', '.club', '.site', '.online']
        features['uncommon_tld'] = 1 if not any(tld in str(url).lower() for tld in ['.com', '.org', '.net', '.edu', '.gov']) else 0
        
        return features
    
    def preprocess_data(self, df):
        """Preprocess the dataset"""
        print("Preprocessing data...")
        
        # Filter out safe URLs for binary classification
        df = df[df['label'].isin(['Phishing', 'Suspected', 'safe'])]
        
        # Create binary labels: 1 for malicious (Phishing/Suspected), 0 for safe
        df['binary_label'] = df['label'].apply(
            lambda x: 1 if x in ['Phishing', 'Suspected'] else 0
        )
        
        # Extract URL features
        print("Extracting URL features...")
        url_features = []
        for url in df['url']:
            features = self.extract_url_features(url)
            url_features.append(features)
        
        # Convert to DataFrame
        features_df = pd.DataFrame(url_features)
        self.feature_names = features_df.columns.tolist()
        
        # Combine with TF-IDF features
        print("Creating TF-IDF features...")
        tfidf_features = self.vectorizer.fit_transform(df['url'].astype(str))
        tfidf_df = pd.DataFrame(
            tfidf_features.toarray(), 
            columns=self.vectorizer.get_feature_names_out()
        )
        
        # Combine all features
        final_features = pd.concat([features_df.reset_index(drop=True), 
                                  tfidf_df.reset_index(drop=True)], axis=1)
        
        return final_features, df['binary_label']
    
    def train_model(self, df):
        """Train the phishing detection model"""
        print("Starting model training...")
        
        # Preprocess data
        X, y = self.preprocess_data(df)
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"Training set size: {X_train.shape[0]}")
        print(f"Test set size: {X_test.shape[0]}")
        print(f"Number of features: {X_train.shape[1]}")
        
        # Train multiple models to find the best one
        models = {
            'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'Logistic Regression': LogisticRegression(random_state=42, max_iter=1000),
            'SVM': SVC(random_state=42, probability=True)
        }
        
        best_accuracy = 0
        best_model = None
        best_model_name = ""
        
        print("\nTraining multiple models...")
        for name, model in models.items():
            print(f"Training {name}...")
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            print(f"{name} Accuracy: {accuracy:.4f}")
            
            if accuracy > best_accuracy:
                best_accuracy = accuracy
                best_model = model
                best_model_name = name
        
        self.model = best_model
        print(f"\nBest model: {best_model_name} with accuracy: {best_accuracy:.4f}")
        
        # Detailed evaluation
        self.evaluate_model(X_test, y_test)
        
        return best_accuracy
    
    def evaluate_model(self, X_test, y_test):
        """Evaluate the model performance"""
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)
        
        print("\n" + "="*50)
        print("MODEL EVALUATION RESULTS")
        print("="*50)
        
        # Accuracy
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Overall Accuracy: {accuracy:.4f}")
        
        # Classification report
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, 
                                 target_names=['Safe', 'Malicious']))
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        print("Confusion Matrix:")
        print(f"True Negatives (Safe correctly identified): {cm[0][0]}")
        print(f"False Positives (Safe misclassified as Malicious): {cm[0][1]}")
        print(f"False Negatives (Malicious misclassified as Safe): {cm[1][0]}")
        print(f"True Positives (Malicious correctly identified): {cm[1][1]}")
        
        # Additional metrics
        tn, fp, fn, tp = cm.ravel()
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print(f"\nPrecision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1-Score: {f1:.4f}")
        
        return accuracy
    
    def predict_url(self, url):
        """Predict if a URL is malicious"""
        if self.model is None:
            raise ValueError("Model not trained yet. Please train the model first.")
        
        # Extract features
        url_features = self.extract_url_features(url)
        features_df = pd.DataFrame([url_features])
        
        # TF-IDF features
        tfidf_features = self.vectorizer.transform([str(url)])
        tfidf_df = pd.DataFrame(
            tfidf_features.toarray(), 
            columns=self.vectorizer.get_feature_names_out()
        )
        
        # Combine features
        final_features = pd.concat([features_df.reset_index(drop=True), 
                                  tfidf_df.reset_index(drop=True)], axis=1)
        
        # Ensure all training features are present
        for col in self.feature_names:
            if col not in final_features.columns:
                final_features[col] = 0
        
        # Reorder columns to match training
        final_features = final_features[self.feature_names + 
                                      list(self.vectorizer.get_feature_names_out())]
        
        # Predict
        prediction = self.model.predict(final_features)[0]
        probability = self.model.predict_proba(final_features)[0]
        
        return {
            'is_malicious': bool(prediction),
            'malicious_probability': float(probability[1]),
            'safe_probability': float(probability[0]),
            'confidence': float(max(probability))
        }
    
    def save_model(self, filename='phishing_detector_model.pkl'):
        """Save the trained model"""
        if self.model is None:
            raise ValueError("No model to save. Please train the model first.")
        
        model_data = {
            'model': self.model,
            'vectorizer': self.vectorizer,
            'feature_names': self.feature_names
        }
        
        joblib.dump(model_data, filename)
        print(f"Model saved as {filename}")
    
    def load_model(self, filename='phishing_detector_model.pkl'):
        """Load a trained model"""
        model_data = joblib.load(filename)
        self.model = model_data['model']
        self.vectorizer = model_data['vectorizer']
        self.feature_names = model_data['feature_names']
        print(f"Model loaded from {filename}")

def load_dataset(file_path):
    """Load dataset from various sources"""
    print(f"Loading dataset from: {file_path}")
    
    # Method 1: Direct CSV file
    try:
        df = pd.read_csv(file_path)
        print("Dataset loaded successfully from CSV file")
        return df
    except Exception as e:
        print(f"Error loading from CSV: {e}")
    
    # Method 2: If you have the data as a variable (for testing)
    try:
        # You can replace this with your actual dataset variable
        from training_data import df  # if you have it in another file
        print("Dataset loaded from variable")
        return df
    except:
        pass
    
    # Method 3: Create sample data for testing
    print("Creating sample dataset for demonstration...")
    sample_data = {
        'url': [
            'https://www.google.com',
            'airtel-merchants.in', 
            'hdfcbanklogin.com',
            'https://www.github.com',
            'icicibank-coin.buzz',
            'https://www.microsoft.com',
            'suspicious-site.xyz',
            'https://www.apple.com'
        ],
        'label': [
            'safe', 'Phishing', 'Phishing', 'safe', 
            'Phishing', 'safe', 'Suspected', 'safe'
        ]
    }
    return pd.DataFrame(sample_data)

def main():
    # === WHERE YOU INPUT YOUR DATASET ===
    
    # Option 1: Load from CSV file (recommended)
    file_path = r"C:\Users\Harsh Sharma\OneDrive\Desktop\proto1\New folder\training_data.csv"  # Change this to your actual file path
    
    # Option 2: If your data is in the same directory as this script
    # file_path = 'training_data.csv'
    
    # Option 3: If you want to use the sample data from the chat
    # You can copy-paste your CSV content into a file and use Option 1
    
    print("="*60)
    print("PHISHING URL DETECTION MODEL TRAINING")
    print("="*60)
    
    # Load your dataset
    df = load_dataset(file_path)
    
    print(f"\nDataset Information:")
    print(f"Shape: {df.shape}")
    print(f"Columns: {df.columns.tolist()}")
    print(f"\nLabel distribution:")
    print(df['label'].value_counts())
    
    # Display first few rows
    print(f"\nFirst 5 rows of the dataset:")
    print(df.head())
    
    # Check if required columns exist
    if 'url' not in df.columns or 'label' not in df.columns:
        print("ERROR: Dataset must contain 'url' and 'label' columns")
        return
    
    # Initialize and train the detector
    detector = PhishingURLDetector()
    
    # Train the model
    print("\n" + "="*60)
    print("STARTING MODEL TRAINING")
    print("="*60)
    
    accuracy = detector.train_model(df)
    
    # Save the model
    print("\n" + "="*60)
    print("SAVING TRAINED MODEL")
    print("="*60)
    
    detector.save_model('phishing_url_detector.pkl')
    
    # Test with some examples
    print("\n" + "="*60)
    print("TESTING WITH SAMPLE URLs")
    print("="*60)
    
    test_urls = [
        "https://www.google.com",      # Safe
        "airtel-merchants.in",        # Phishing
        "hdfcbanklogin.com",          # Phishing  
        "https://www.github.com",     # Safe
        "icicibank-coin.buzz",        # Phishing
        "https://www.microsoft.com",  # Safe
        "suspicious-site.xyz",        # Suspected
        "bankofbarodafin.in"          # Suspected
    ]
    
    for url in test_urls:
        result = detector.predict_url(url)
        status = "MALICIOUS" if result['is_malicious'] else "SAFE"
        confidence_level = "HIGH" if result['confidence'] > 0.8 else "MEDIUM" if result['confidence'] > 0.6 else "LOW"
        
        print(f"URL: {url}")
        print(f"Status: {status} ({confidence_level} confidence)")
        print(f"Malicious Probability: {result['malicious_probability']:.4f}")
        print(f"Safe Probability: {result['safe_probability']:.4f}")
        print(f"Confidence: {result['confidence']:.4f}")
        print("-" * 50)

# Alternative function to use if you want to load your specific dataset
def train_with_your_data():
    """Use this function if you have the dataset in the same script"""
    
    # Convert your CSV data to a DataFrame
    data = """
    S. No,Critical Sector Entity Name,Corresponding CSE Domain Name,url,label,Evidence file name,Source of detection
    1,Airtel,airtel.in,airtel-merchants.in,Phishing,airtel-merchants.in.pdf,
    2,Airtel,airtel.in,airtelrecharge.co.in,Phishing,airtelrecharge.co.in.pdf,
    # ... (paste your entire CSV data here)
    """
    
    # You can create a CSV file from your data and then load it
    with open('training_data.csv', 'w') as f:
        f.write(data)
    
    # Now run the main function
    main()

if __name__ == "__main__":
    main()