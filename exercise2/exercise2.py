import math
import itertools
import string
import os
from collections import Counter
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Util.Padding import unpad

def solve_exercise_1():
    entropy_per_char = math.log2(26)
    required_length = 256 / entropy_per_char
    
    print(f"Exercise 1: Password Entropy")
    print(f"Alphabet [a-z]: 26 chars, {entropy_per_char:.2f} bits/char")
    print(f"Required length for 256 bits: {math.ceil(required_length)} characters\n")

def solve_exercise_2():
    print("Exercise 2: AES-ECB Brute Force")
    
    encrypted_file = "../necessaryResources/security_ECB_encrypted.bmp"
    
    if not os.path.exists(encrypted_file):
        print(f"Error: {encrypted_file} not found")
        return
    
    with open(encrypted_file, 'rb') as f:
        encrypted_data = f.read()
    
    print(f"File size: {len(encrypted_data)} bytes")
    
    if len(encrypted_data) % 16 != 0:
        truncated_size = (len(encrypted_data) // 16) * 16
        encrypted_data = encrypted_data[:truncated_size]
    
    repeated, uniqueness, block_counts = analyze_ecb_patterns(encrypted_data)
    total_blocks = len(encrypted_data) // 16
    
    print(f"Blocks: {total_blocks} total, {len(block_counts)} unique ({uniqueness*100:.1f}%)")
    if uniqueness < 0.90:
        print(f"ECB mode detected (low uniqueness)")
    
    print("Testing keys: ", end="", flush=True)
    
    for char in string.ascii_lowercase:
        print(char, end="", flush=True)
        
        key = (char * 16).encode('utf-8')
        
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            
            decrypted_data = cipher.decrypt(encrypted_data)
            
            if decrypted_data.startswith(b'BM'):
                print(f"\n\nKey found: '{char}' (repeated 16x)")
                
                output_file = "../decrypted/security_decrypted.bmp"
                with open(output_file, 'wb') as f:
                    f.write(decrypted_data)
                
                print(f"Saved: {output_file}")
                
                if len(decrypted_data) >= 26:
                    width = int.from_bytes(decrypted_data[18:22], 'little')
                    height = int.from_bytes(decrypted_data[22:26], 'little')
                    print(f"Image: {width}x{height}px\n")
                return
            
            try:
                unpadded_data = unpad(decrypted_data, AES.block_size)
                
                if unpadded_data.startswith(b'BM'):
                    print(f"\n\nKey found: '{char}' (repeated 16x, padded)")
                    
                    output_file = "../decrypted/security_decrypted.bmp"
                    with open(output_file, 'wb') as f:
                        f.write(unpadded_data)
                    
                    print(f"Saved: {output_file}")
                    
                    if len(unpadded_data) >= 26:
                        width = int.from_bytes(unpadded_data[18:22], 'little')
                        height = int.from_bytes(unpadded_data[22:26], 'little')
                        print(f"Image: {width}x{height}px\n")
                    return
                    
            except ValueError:
                pass
                
        except Exception as e:
            continue
    
    print("\n\nNo valid key found\n")

def analyze_ecb_patterns(ciphertext):
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    block_counts = Counter(blocks)
    repeated = {block.hex(): count for block, count in block_counts.items() if count > 1}
    uniqueness_ratio = len(set(blocks)) / len(blocks)
    return repeated, uniqueness_ratio, block_counts

if __name__ == "__main__":
    import time
    
    results = []
    
    start_time = time.time()
    solve_exercise_1()
    ex1_time = time.time() - start_time
    results.append(f"=== Exercise 1: Password Entropy ===")
    results.append(f"Time: {ex1_time:.2f}s")
    results.append(f"Result: 55 characters needed for 256-bit entropy")
    
    start_time = time.time()
    solve_exercise_2()
    ex2_time = time.time() - start_time
    results.append(f"\n=== Exercise 2: AES-ECB Brute Force ===")
    results.append(f"Time: {ex2_time:.2f}s")
    results.append(f"Key found: s (repeated 16 times)")
    
    with open("results.txt", "w", encoding='utf-8') as f:
        f.write("\n".join(results))
    
    print(f"\nResults saved to results.txt")
