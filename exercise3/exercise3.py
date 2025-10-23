import hashlib
import string
import base64
import time
from passlib.hash import md5_crypt, sha256_crypt

def find_md5_collision():
    """Znajdź dwa hasła z identycznymi pierwszymi 6 znakami MD5"""
    seen = {}
    counter = 0
    
    while True:
        password = f"pass{counter}"
        md5_hash = hashlib.md5(password.encode()).hexdigest()
        prefix = md5_hash[:6]
        
        if prefix in seen:
            print(f"\n=== Kolizja MD5 (pierwsze 6 znakow) ===")
            print(f"Haslo 1: {seen[prefix]}")
            print(f"MD5: {hashlib.md5(seen[prefix].encode()).hexdigest()}")
            print(f"Haslo 2: {password}")
            print(f"MD5: {md5_hash}")
            print(f"Wspolny prefix: {prefix}")
            return seen[prefix], password
        
        seen[prefix] = password
        counter += 1
        
        if counter % 10000 == 0:
            print(f"Sprawdzono {counter} hasel...")

def crack_argon2(hash_string, passwords):
    """Specjalna funkcja dla Argon2"""
    try:
        from argon2.low_level import hash_secret_raw, Type
        
        parts = hash_string.split('$')
        params_dict = {}
        for param in parts[3].split(','):
            k, v = param.split('=')
            params_dict[k] = int(v)
        
        salt_b64 = parts[4]
        target_hash = parts[5]
        
        while len(salt_b64) % 4 != 0:
            salt_b64 += '='
        salt_bytes = base64.b64decode(salt_b64)
        
        for i, password in enumerate(passwords):
            try:
                hash_result = hash_secret_raw(
                    secret=password.encode(),
                    salt=salt_bytes,
                    time_cost=params_dict['t'],
                    memory_cost=params_dict['m'],
                    parallelism=params_dict['p'],
                    hash_len=32,
                    type=Type.ID
                )
                
                hash_b64 = base64.b64encode(hash_result).decode().rstrip('=')
                
                if hash_b64 == target_hash:
                    print(f"[OK] Znalezione haslo: {password} (po {i+1} probach)")
                    return password
            except:
                continue
            
            if (i + 1) % 100 == 0:
                print(f"Sprawdzono {i + 1} hasel...")
        
        return None
    except ImportError:
        print("[ERROR] Brak biblioteki argon2-cffi")
        return None

def crack_hash(hash_string, passwords, salt_suffix=False):
    """Zlam hash uzywajac slownika"""
    print(f"\n=== Atak na hash ===")
    print(f"Hash: {hash_string[:60]}...")
    
    if hash_string.startswith('$argon2'):
        print("Typ: Argon2")
        parts = hash_string.split('$')
        print(f"Parametry: {parts[3]}")
        return crack_argon2(hash_string, passwords)
    
    if not salt_suffix:
        if hash_string.startswith('$1$'):
            print("Typ: MD5-crypt")
            salt = hash_string.split('$')[2]
            
            for i, password in enumerate(passwords):
                try:
                    test_hash = md5_crypt.using(salt=salt).hash(password)
                    if test_hash == hash_string:
                        print(f"[OK] Znalezione haslo: {password} (po {i+1} probach)")
                        return password
                except:
                    continue
                
                if (i + 1) % 500 == 0:
                    print(f"Sprawdzono {i + 1} hasel...")
                    
        elif hash_string.startswith('$5$'):
            print("Typ: SHA256-crypt")
            parts = hash_string.split('$')
            rounds = int(parts[2].split('=')[1]) if 'rounds=' in parts[2] else 5000
            salt = parts[3]
            print(f"Parametry: rounds={rounds}")
            
            for i, password in enumerate(passwords):
                try:
                    test_hash = sha256_crypt.using(rounds=rounds, salt=salt).hash(password)
                    if test_hash == hash_string:
                        print(f"[OK] Znalezione haslo: {password} (po {i+1} probach)")
                        return password
                except:
                    continue
                
                if (i + 1) % 500 == 0:
                    print(f"Sprawdzono {i + 1} hasel...")
    else:
        print("Typ: MD5-crypt z pieprzem [a-z]")
        salt = hash_string.split('$')[2]
        
        for i, password in enumerate(passwords):
            for char in string.ascii_lowercase:
                salted_password = password + char
                try:
                    test_hash = md5_crypt.using(salt=salt).hash(salted_password)
                    
                    if test_hash == hash_string:
                        print(f"[OK] Znalezione haslo: {password}")
                        print(f"[OK] Pieprz: {char}")
                        print(f"[OK] Pelne haslo: {salted_password}")
                        return salted_password
                except:
                    continue
            
            if (i + 1) % 100 == 0:
                print(f"Sprawdzono {i + 1} hasel (x 26 wariantow)...")
    
    print("[FAIL] Nie znaleziono hasla")
    return None

def main():
    """Main function to run both parts of the cryptanalysis assignment"""
    output_results = []
    
    print("=== Exercise 3: MD5 Collisions & Password Cracking ===\n")
    
    print("Czesc 1: Kolizja MD5 (pierwsze 6 znakow)")
    start_time = time.time()
    pass1, pass2 = find_md5_collision()
    collision_time = time.time() - start_time
    
    output_results.append("=== Czesc 1: Kolizja MD5 ===")
    output_results.append(f"Time: {collision_time:.2f}s")
    output_results.append(f"Haslo 1: {pass1}")
    output_results.append(f"Haslo 2: {pass2}")
    output_results.append(f"Prefix: {hashlib.md5(pass1.encode()).hexdigest()[:6]}")
    
    print("\n" + "="*60)
    print("Czesc 2: Atak slownikowy na hash'e")
    print("="*60)
    
    with open("../necessaryResources/passwords.txt", "r", encoding='utf-8') as f:
        passwords = [line.strip() for line in f if line.strip()]
    
    print(f"\nZaladowano {len(passwords)} hasel ze slownika")
    
    hashes = [
        ("$1$k8nhEGc9$MwWuWMnHqzGdszCwI98RZ0", False, "MD5-crypt"),
        ("$5$rounds=10000$ujmXZ4IqnXl.Bplf$4lcwpQwc.kZFIuCrV8Mgg8bP.Mv.jxx9NitjrqQPK8/", False, "SHA256-crypt"),
        ("$argon2id$v=19$m=65536,t=3,p=4$GWMMQYgxJmQshdB6L0UIgQ$+glO5pBsNQ6Fb80yakwkzUfSXdX9nQM0ygF2ZNJ5DwI", False, "Argon2"),
        ("$1$o8ZWp.W5$FIkSXN.lufeIWvllfQW9l1", True, "MD5-crypt+pepper")
    ]
    
    output_results.append("\n=== Czesc 2: Atak slownikowy ===")
    results = []
    total_time = 0
    
    for hash_string, use_salt, hash_type in hashes:
        start_time = time.time()
        result = crack_hash(hash_string, passwords, salt_suffix=use_salt)
        crack_time = time.time() - start_time
        total_time += crack_time
        results.append((hash_string, result, hash_type, crack_time))
        output_results.append(f"{hash_type}: {result if result else 'FAILED'} ({crack_time:.2f}s)")
    
    output_results.append(f"\nTotal cracking time: {total_time:.2f}s")
    
    print("\n" + "="*60)
    print("PODSUMOWANIE WYNIKOW")
    print("="*60)
    for hash_string, password, hash_type, crack_time in results:
        status = "[OK] ZLAMANY" if password else "[FAIL] NIEZNANY"
        print(f"\n{status}")
        print(f"Type: {hash_type}")
        print(f"Hash: {hash_string[:50]}...")
        if password:
            print(f"Haslo: {password}")
        print(f"Time: {crack_time:.2f}s")
    
    with open("results.txt", "w", encoding='utf-8') as f:
        f.write("\n".join(output_results))
    
    print(f"\n\nResults saved to results.txt")

if __name__ == "__main__":
    main()
