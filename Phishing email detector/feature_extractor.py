import re
import nltk
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from sklearn.base import BaseEstimator, TransformerMixin

nltk.download('stopwords', quiet=True)
nltk.download('punkt', quiet=True)
nltk.download('punkt_tab', quiet=True)

class EmailFeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.stemmer = PorterStemmer()
        self.stop_words = set(stopwords.words('english'))

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return [self._clean_text(text) for text in X]

    def _clean_text(self, text):
        if not isinstance(text, str):
            text = str(text)
            
        # Convert to lowercase
        text = text.lower()
        
        # Remove URLs (replace with 'httpaddr' feature)
        text = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', 'httpaddr', text)
        
        # Remove email addresses
        text = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'emailaddr', text)
        
        # Remove numbers
        text = re.sub(r'\b\d+\b', 'number', text)
        
        # Remove special characters and punctuation
        text = re.sub(r'[^\w\s]', ' ', text)
        
        # Tokenization and Stemming
        tokens = text.split()
        cleaned_tokens = [self.stemmer.stem(word) for word in tokens if word not in self.stop_words]
        
        return ' '.join(cleaned_tokens)

# Function for advanced feature extraction (URL count, etc.)
def extract_advanced_features(text):
    features = {}
    features['num_urls'] = len(re.findall(r'http[s]?://', text))
    features['num_exclamations'] = text.count('!')
    features['has_urgent_words'] = int(any(word in text.lower() for word in ['urgent', 'immediate', 'action required', 'suspended', 'verify', 'expire', 'locked']))
    features['has_financial_words'] = int(any(word in text.lower() for word in ['bank', 'account', 'payment', 'paypal', 'credit', 'invoice', 'remit']))
    return features
