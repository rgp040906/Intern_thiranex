import joblib
from feature_extractor import extract_advanced_features

class PhishingDetector:
    def __init__(self, model_path='models/phishing_model.pkl'):
        try:
            self.model = joblib.load(model_path)
        except Exception as e:
            print(f"Error loading model: {e}")
            self.model = None

    def predict(self, email_text):
        if not self.model:
            return None, 0.0, {}
            
        prediction = self.model.predict([email_text])[0]
        probabilities = self.model.predict_proba([email_text])[0]
        confidence = probabilities[prediction] * 100
        
        # Advanced feature analysis for risk score
        adv_features = extract_advanced_features(email_text)
        
        # Adjust risk score based on advanced features if needed
        risk_score = probabilities[1] * 100 # Probability of being phishing
        
        # Add slight boosts to risk score based on clear indicators if it's borderline
        if adv_features['num_urls'] > 2:
            risk_score = min(99.9, risk_score + 10)
        if adv_features['has_urgent_words']:
            risk_score = min(99.9, risk_score + 15)
        if adv_features['has_financial_words']:
            risk_score = min(99.9, risk_score + 10)
            
        return prediction, risk_score, adv_features

if __name__ == "__main__":
    detector = PhishingDetector()
    test_email = "URGENT! Verify your bank account immediately."
    pred, conf, _ = detector.predict(test_email)
    label = "PHISHING EMAIL" if pred == 1 else "SAFE EMAIL"
    print(f"Input: {test_email}")
    print(f"Prediction: {label}")
    print(f"Risk Score: {conf:.1f}%")
