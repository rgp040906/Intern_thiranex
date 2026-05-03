import hashlib
import requests
from zxcvbn import zxcvbn
from typing import List, Tuple

def hash_password(password: str) -> str:
    """Converts password into a SHA-256 encrypted hash."""
    return hashlib.sha256(password.encode()).hexdigest()

def check_pwned_api(password: str) -> int:
    """
    Checks the Have I Been Pwned API safely using k-anonymity.
    Returns the number of times the password has appeared in data breaches.
    """
    if not password:
        return 0
        
    try:
        # Create SHA-1 hash of the password (required by HIBP API)
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        # Get the first 5 characters (prefix) and the rest (suffix)
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # Send only the 5-character prefix to the API
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            # The API returns all suffixes that match the prefix, along with their breach count
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return int(count)
        return 0
    except Exception as e:
        print(f"Error checking Pwned API: {e}")
        return 0

def analyze_password(password: str) -> Tuple[int, str, List[str], int]:
    """
    Analyzes password using Dropbox's zxcvbn and Have I Been Pwned API.
    Returns (score, strength_level, suggestions, pwned_count).
    """
    if not password:
        return 0, "Very Weak", ["Password cannot be empty."], 0

    # 1. zxcvbn analysis
    result = zxcvbn(password)
    zxcvbn_score = result['score']  # 0 to 4
    suggestions = result['feedback']['suggestions']
    warning = result['feedback']['warning']
    
    if warning:
        suggestions.insert(0, f"Warning: {warning}")

    # 2. Have I Been Pwned check
    pwned_count = check_pwned_api(password)
    
    if pwned_count > 0:
        suggestions.append(f"CRITICAL: Found in {pwned_count:,} real-world data breaches!")
        # If it's heavily pwned, force the score to 0 regardless of complexity
        if pwned_count > 10:
            zxcvbn_score = 0
            
    # Normalize score to our 0-7 scale for the GUI
    # zxcvbn scale is 0-4
    score = int((zxcvbn_score / 4) * 7)

    # Strength Level based on zxcvbn
    if zxcvbn_score == 0:
        strength = "Very Weak"
    elif zxcvbn_score == 1:
        strength = "Weak"
    elif zxcvbn_score == 2:
        strength = "Medium"
    elif zxcvbn_score == 3:
        strength = "Strong"
    else:
        strength = "Very Strong"

    # Provide positive feedback if no suggestions
    if not suggestions and pwned_count == 0:
        suggestions.append("Great password! Safe from known breaches.")

    return score, strength, suggestions, pwned_count
