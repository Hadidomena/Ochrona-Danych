import random
import time
import math
import itertools
import string
import os
from Cryptodome.Cipher import ARC4


# Language-specific alphabets
ALPHABETS = {
    'english': "abcdefghijklmnopqrstuvwxyz",
    'french': "abcdefghijklmnopqrstuvwxyzàâäéèêëïîôöùûüÿç", 
    'polish': "abcdefghijklmnopqrstuvwxyząćęłńóśźż"
}

CHAR_FREQUENCIES = {
    'english': {
        'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7,
        's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8,
        'u': 2.8, 'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0,
        'p': 1.9, 'b': 1.3, 'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15,
        'q': 0.10, 'z': 0.07
    },
    'french': {
        'e': 14.7, 'a': 7.6, 'i': 7.5, 's': 7.9, 'n': 7.1, 'r': 6.6,
        't': 7.2, 'l': 5.5, 'u': 6.3, 'o': 5.3, 'd': 3.7, 'c': 3.3,
        'p': 3.0, 'm': 3.0, 'é': 1.9, 'è': 0.7, 'à': 0.5, 'ê': 0.2,
        'ç': 0.2, 'ô': 0.1, 'î': 0.1, 'ù': 0.1, 'û': 0.1, 'â': 0.1,
        'v': 1.6, 'q': 1.4, 'f': 1.1, 'b': 0.9, 'g': 0.9, 'h': 0.7,
        'x': 0.4, 'j': 0.5, 'y': 0.3, 'z': 0.1, 'w': 0.1, 'k': 0.1
    },
    'polish': {
        'a': 10.5, 'e': 8.9, 'i': 8.2, 'o': 7.8, 'n': 5.5, 'r': 4.7,
        'z': 5.6, 's': 4.7, 'w': 4.6, 't': 3.9, 'c': 4.0, 'y': 3.8,
        'k': 3.5, 'd': 3.3, 'p': 3.1, 'm': 2.8, 'u': 2.5, 'l': 2.1,
        'j': 2.3, 'ł': 1.8, 'ą': 0.9, 'ę': 1.1, 'ć': 0.4, 'ń': 0.2,
        'ó': 0.8, 'ś': 0.7, 'ź': 0.06, 'ż': 0.83, 'b': 1.5, 'g': 1.4,
        'h': 1.1, 'f': 0.3, 'v': 0.1, 'x': 0.0, 'q': 0.0
    }
}

# Common bigrams for different languages
COMMON_BIGRAMS = {
    'english': ['th', 'he', 'in', 'er', 'an', 're', 'ed', 'nd', 'on', 'en', 'at', 'ou', 'it', 'is', 'or', 'ti', 'hi', 'st', 'ar', 'ne'],
    'french': ['es', 'de', 're', 'le', 'en', 'on', 'nt', 'er', 'te', 'la', 'qu', 'ti', 'se', 'ou', 'et', 'in', 'me', 'an', 'ur', 'ie'],
    'polish': ['ie', 'na', 'ni', 'si', 'te', 'ra', 'ko', 'to', 'ze', 'po', 'ne', 'ka', 'ta', 'la', 'ro', 'ch', 'ci', 'ty', 'em', 'wy']
}


def smart_frequency_attack(language):
    """Single-pass frequency attack using most frequent characters"""
    alphabet = ALPHABETS[language]
    expected_freq = CHAR_FREQUENCIES[language]
    
    try:
        with open(f"../afterCipher/{language}.txt", "r", encoding='utf-8') as file:
            encrypted_text = file.read().lower()
    except UnicodeDecodeError:
        with open(f"../afterCipher/{language}.txt", "r", encoding='latin-1') as file:
            encrypted_text = file.read().lower()

    char_counts = {}
    total_chars = 0
    for char in encrypted_text:
        if char in alphabet:
            char_counts[char] = char_counts.get(char, 0) + 1
            total_chars += 1
    
    if not char_counts:
        return 0, float('inf')
    
    most_frequent_cipher = max(char_counts, key=char_counts.get)
    most_frequent_lang = max(expected_freq, key=expected_freq.get)
    
    cipher_pos = alphabet.index(most_frequent_cipher)
    lang_pos = alphabet.index(most_frequent_lang)
    predicted_shift = (cipher_pos - lang_pos) % len(alphabet)
    
    decrypted_text = decrypt_with_shift(encrypted_text, predicted_shift, alphabet)
    observed_freq = calculate_frequency(decrypted_text, alphabet)
    chi_squared = chi_squared_test(observed_freq, expected_freq, alphabet)
    
    return predicted_shift, chi_squared


def bigram_attack(language):
    alphabet = ALPHABETS[language]
    common_bigrams = COMMON_BIGRAMS[language]
    alphabet_size = len(alphabet)
    try:
        with open(f"../afterCipher/{language}.txt", "r", encoding='utf-8') as file:
            encrypted_text = file.read().lower()
    except UnicodeDecodeError:
        with open(f"../afterCipher/{language}.txt", "r", encoding='latin-1') as file:
            encrypted_text = file.read().lower()
    
    shift_scores = []
    
    for shift in range(alphabet_size):
        shifted_bigrams = []
        for bigram in common_bigrams:
            if len(bigram) == 2 and all(c in alphabet for c in bigram):
                shifted_bigram = ""
                for char in bigram:
                    old_pos = alphabet.index(char)
                    new_pos = (old_pos + shift) % alphabet_size
                    shifted_bigram += alphabet[new_pos]
                shifted_bigrams.append(shifted_bigram)
        bigram_score = 0
        for shifted_bigram in shifted_bigrams:
            bigram_score += encrypted_text.count(shifted_bigram)
        
        shift_scores.append((shift, bigram_score, shifted_bigrams[:3]))
    shift_scores.sort(key=lambda x: x[1], reverse=True)
    best_shift, best_score, best_patterns = shift_scores[0]
    for i, (shift, score, patterns) in enumerate(shift_scores[:3]):
        marker = " ← BEST" if i == 0 else ""
    
    return best_shift, best_score
def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0
        
    frequency = {}
    for byte in data:
        frequency[byte] = frequency.get(byte, 0) + 1
        
    entropy = 0
    length = len(data)
    for count in frequency.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
        
    return entropy
def is_likely_plaintext(data, entropy_threshold=7.0):
    """Check if decrypted data looks like plaintext based on entropy"""
    if not data:
        return False
        
    entropy = calculate_entropy(data)
        
    if entropy > entropy_threshold:
        return False
        
    try:
        text = data.decode('utf-8', errors='ignore')
        printable_ratio = sum(1 for c in text if c.isprintable()) / len(text)
        return printable_ratio > 0.8 and entropy < entropy_threshold
    except:
        return False
    
def secondPart():
    """Perform brute force attacks on RC4 encrypted files using entropy verification"""
    
    def rc4_decrypt(ciphertext, key):
        """Decrypt data using RC4"""
        if ARC4 is None:
            return None
        try:
            cipher = ARC4.new(key.encode('utf-8'))
            return cipher.decrypt(ciphertext)
        except:
            return None
    
    
    
    def brute_force_rc4(filename):
        """Brute force RC4 encrypted file with 3-character keys [a-z]{3}"""
        try:
            with open(filename, 'rb') as f:
                ciphertext = f.read()
        except FileNotFoundError:
            return None, None, f"File {filename} not found!"
        
        if ARC4 is None:
            return None, None, "RC4 functionality not available - Crypto library not installed"
        
        best_key = None
        best_entropy = float('inf')
        best_plaintext = None
        
        for key_tuple in itertools.product(string.ascii_lowercase, repeat=3):
            key = ''.join(key_tuple)
            
            plaintext = rc4_decrypt(ciphertext, key)
            
            if plaintext is not None:
                entropy = calculate_entropy(plaintext)
                
                if is_likely_plaintext(plaintext, entropy_threshold=7.0):
                    if entropy < best_entropy:
                        best_entropy = entropy
                        best_key = key
                        best_plaintext = plaintext
                        
                        if entropy < 5.0:
                            break
        
        if best_key and best_plaintext:
            output_filename = f"../decrypted/decrypted_{filename.replace('.rc4', '.txt')}"
            try:
                with open(output_filename, 'wb') as f:
                    f.write(best_plaintext)
            except:
                pass
        
        status = "Success" if best_key else "Failed"
        return best_key, best_entropy, status
    
    files = ['../necessaryResources/crypto.rc4', '../necessaryResources/crypto2.rc4']
    results = []
    
    for filename in files:
        start_time = time.time()
        key, entropy, status = brute_force_rc4(filename)
        execution_time = time.time() - start_time
        results.append({
            'File': filename,
            'Key Found': key if key else 'None',
            'Entropy': f"{entropy:.3f}" if entropy is not None and entropy != float('inf') else 'N/A',
            'Status': status,
            'Time': f"{execution_time:.3f}s"
        })
    
    print("\n" + "="*75)
    print("RC4 BRUTE FORCE ATTACK RESULTS - PART 2")
    print("="*75)
    print(f"{'File':<15} {'Key Found':<10} {'Entropy':<10} {'Status':<15} {'Time':<10}")
    print("-" * 75)
    
    for result in results:
        print(f"{result['File']:<15} {result['Key Found']:<10} {result['Entropy']:<10} {result['Status']:<15} {result['Time']:<10}")
    
    successful_attacks = sum(1 for r in results if r['Status'] == 'Success')
    print("-" * 75)
    print(f"Successful Attacks: {successful_attacks}/{len(results)}")
    
    summary = []
    for result in results:
        filename = os.path.basename(result['File'])
        key = result['Key Found'] if result['Key Found'] != 'None' else None
        entropy = float(result['Entropy']) if result['Entropy'] != 'N/A' else None
        if key:
            summary.append((filename, key, entropy))
    
    return summary
def cyclicalCipher(language):
    alphabet = ALPHABETS[language]
    alphabet_size = len(alphabet)
    
    
    move = random.randint(1, alphabet_size - 1)
    
    text = ""
    try:
        with open("../texts/" + language + ".txt", "r", encoding='utf-8') as file:
            text = file.read()
            text = text.lower()
    except UnicodeDecodeError:
        with open("../texts/" + language + ".txt", "r", encoding='latin-1') as file:
            text = file.read()
            text = text.lower()

    afterCipher = ""
    for char in text:
        if char in alphabet:
            old_pos = alphabet.index(char)
            new_pos = (old_pos + move) % alphabet_size
            afterCipher += alphabet[new_pos]
        else:
            afterCipher += char
    with open("../afterCipher/" + language + ".txt", "w", encoding='utf-8') as file:
        file.write(afterCipher)
    
    return move


def firstPart():
    """Encrypt texts from texts directory and break them using multiple methods"""
    languages = ['english', 'french', 'polish']
    
    actual_shifts = {}
    for language in languages:
        actual_shifts[language] = cyclicalCipher(language)
    
    methods = [
        ("Chi-squared", frequency_attack),
        ("Smart Frequency", smart_frequency_attack),
        ("Bigram Analysis", bigram_attack)
    ]
    
    results = []
    
    for language in languages:
        for method_name, method_func in methods:
            start_time = time.time()
            predicted_shift, score = method_func(language)
            execution_time = time.time() - start_time
            correct = predicted_shift == actual_shifts[language]
            
            results.append({
                'Language': language.title(),
                'Method': method_name,
                'Actual Shift': actual_shifts[language],
                'Predicted Shift': predicted_shift,
                'Correct': 'OK' if correct else 'FAIL',
                'Score': f"{score:.2f}",
                'Time': f"{execution_time:.3f}s"
            })
    
    print("\n" + "="*95)
    print("CRYPTANALYSIS RESULTS - PART 1")
    print("="*95)
    print(f"{'Language':<10} {'Method':<20} {'Actual':<8} {'Predicted':<10} {'Correct':<8} {'Score':<10} {'Time':<8}")
    print("-" * 95)
    
    for result in results:
        print(f"{result['Language']:<10} {result['Method']:<20} {result['Actual Shift']:<8} "
              f"{result['Predicted Shift']:<10} {result['Correct']:<8} {result['Score']:<10} {result['Time']:<8}")
    
    total_tests = len(results)
    correct_tests = sum(1 for r in results if r['Correct'] == 'OK')
    accuracy = (correct_tests / total_tests) * 100
    
    print("-" * 95)
    print(f"Overall Accuracy: {correct_tests}/{total_tests} ({accuracy:.1f}%)")
    
    summary = []
    for lang in languages:
        lang_results = [r for r in results if r['Language'] == lang.title()]
        if lang_results:
            shift = lang_results[0]['Actual Shift']
            best = min(lang_results, key=lambda x: float('inf') if x['Correct'] == 'FAIL' else float(x['Score']))
            summary.append((lang, shift, float(best['Score'])))
    
    return summary
    
    return results

def calculate_frequency(text, alphabet):
    """Calculate character frequencies in text as percentages"""
    char_count = {}
    total_alphabet_chars = 0
    
    for char in text:
        if char in alphabet:
            char_count[char] = char_count.get(char, 0) + 1
            total_alphabet_chars += 1
    
    frequencies = {}
    for char in alphabet:
        if char in char_count:
            frequencies[char] = (char_count[char] / total_alphabet_chars) * 100
        else:
            frequencies[char] = 0.0
            
    return frequencies


def chi_squared_test(observed_freq, expected_freq, alphabet):
    """Calculate chi-squared statistic to measure how well frequencies match"""
    chi_squared = 0.0
    
    for char in alphabet:
        expected = expected_freq.get(char, 0.01)
        observed = observed_freq.get(char, 0.0)
        
        if expected == 0.0:
            expected = 0.01
        
        chi_squared += ((observed - expected) ** 2) / expected
    
    return chi_squared


def decrypt_with_shift(encrypted_text, shift, alphabet):
    """Decrypt text using a specific shift value"""
    alphabet_size = len(alphabet)
    decrypted = ""
    
    for char in encrypted_text:
        if char in alphabet:
            old_pos = alphabet.index(char)
            new_pos = (old_pos - shift) % alphabet_size
            decrypted += alphabet[new_pos]
        else:
            decrypted += char
    
    return decrypted


def frequency_attack(language):
    """Perform frequency analysis attack on encrypted text"""
    alphabet = ALPHABETS[language]
    expected_freq = CHAR_FREQUENCIES[language]
    alphabet_size = len(alphabet)
    
    try:
        with open(f"../afterCipher/{language}.txt", "r", encoding='utf-8') as file:
            encrypted_text = file.read().lower()
    except UnicodeDecodeError:
        with open(f"../afterCipher/{language}.txt", "r", encoding='latin-1') as file:
            encrypted_text = file.read().lower()
    
    best_shift = 0
    best_chi_squared = float('inf')
    best_decrypted = ""
    
    for shift in range(alphabet_size):
        decrypted_text = decrypt_with_shift(encrypted_text, shift, alphabet)
        observed_freq = calculate_frequency(decrypted_text, alphabet)
        chi_squared = chi_squared_test(observed_freq, expected_freq, alphabet)
        
        if chi_squared < best_chi_squared:
            best_chi_squared = chi_squared
            best_shift = shift
            best_decrypted = decrypted_text
    
    with open(f"../decrypted/decrypted_{language}.txt", "w", encoding='utf-8') as file:
        file.write(best_decrypted)
    
    return best_shift, best_chi_squared


def main():
    """Main function to run both parts of the cryptanalysis assignment"""
    results = []
    
    print("\nPART 1: Cyclical Cipher Analysis")
    start_time = time.time()
    part1_results = firstPart()
    part1_time = time.time() - start_time
    results.append(f"=== PART 1: Cyclical Cipher Analysis ===")
    results.append(f"Time: {part1_time:.2f}s")
    if part1_results:
        for lang, shift, chi in part1_results:
            results.append(f"{lang}: shift={shift}, chi^2={chi:.2f}")
    
    print("\nPART 2: RC4 Brute Force Analysis")
    start_time = time.time()
    part2_results = secondPart()
    part2_time = time.time() - start_time
    results.append(f"\n=== PART 2: RC4 Brute Force Analysis ===")
    results.append(f"Time: {part2_time:.2f}s")
    if part2_results:
        for filename, key, entropy in part2_results:
            results.append(f"{filename}: key={key}, entropy={entropy:.2f}")
    
    with open("results.txt", "w", encoding='utf-8') as f:
        f.write("\n".join(results))
    
    print(f"\nResults saved to results.txt")


if __name__ == "__main__":
    main()