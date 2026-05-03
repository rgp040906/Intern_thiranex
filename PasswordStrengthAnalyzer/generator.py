import string
import random

def generate_password(length: int = 12) -> str:
    """Generates a secure password of given length."""
    if length < 8:
        length = 8
        
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    numbers = string.digits
    symbols = string.punctuation

    # Ensure at least one of each type
    password_chars = [
        random.choice(lower),
        random.choice(upper),
        random.choice(numbers),
        random.choice(symbols)
    ]

    # Fill the rest
    all_chars = lower + upper + numbers + symbols
    for _ in range(length - 4):
        password_chars.append(random.choice(all_chars))

    random.shuffle(password_chars)
    return "".join(password_chars)
