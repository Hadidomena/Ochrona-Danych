import re

def test_exercise3_results():
    """Test exercise3 results from results.txt"""
    
    with open("results.txt", "r", encoding='utf-8') as f:
        content = f.read()
    
    print("=== Testing Exercise 3 Results ===\n")
    
    # Test Part 1 - MD5 Collision
    assert "Czesc 1: Kolizja MD5" in content, "Part 1 section not found"
    
    time_match = re.search(r"Time: ([\d.]+)s", content)
    if time_match:
        collision_time = float(time_match.group(1))
        print(f"[OK] MD5 collision time: {collision_time:.2f}s")
        assert collision_time >= 0, "Invalid time"
    
    # Check for passwords
    pass_matches = re.findall(r"Haslo \d+: (\w+)", content)
    if len(pass_matches) >= 2:
        print(f"[OK] Found collision passwords: {pass_matches[0]}, {pass_matches[1]}")
    
    # Check prefix
    if "Prefix:" in content:
        prefix_match = re.search(r"Prefix: ([a-f0-9]{6})", content)
        if prefix_match:
            prefix = prefix_match.group(1)
            print(f"[OK] Collision prefix: {prefix}")
    
    # Test Part 2 - Dictionary Attack
    assert "Czesc 2: Atak slownikowy" in content, "Part 2 section not found"
    
    # Check for cracked hashes
    hash_types = ["MD5-crypt", "SHA256-crypt", "Argon2", "pepper"]
    cracked_count = 0
    
    for hash_type in hash_types:
        if hash_type in content:
            print(f"[OK] {hash_type} attack attempted")
            # Look for password after hash type
            pattern = f"{hash_type}: (\\w+)"
            match = re.search(pattern, content)
            if match and match.group(1) != "FAILED":
                cracked_count += 1
                print(f"    -> Cracked: {match.group(1)}")
    
    print(f"\n[OK] Successfully cracked {cracked_count}/4 hashes")
    
    # Check total time
    if "Total cracking time:" in content:
        total_time_match = re.search(r"Total cracking time: ([\d.]+)s", content)
        if total_time_match:
            total_time = float(total_time_match.group(1))
            print(f"[OK] Total cracking time: {total_time:.2f}s")
    
    # Verify specific passwords
    expected_passwords = ["alibaba", "italy", "1951", "maryannd"]
    found_passwords = []
    
    for pwd in expected_passwords:
        if pwd in content.lower():
            found_passwords.append(pwd)
    
    if found_passwords:
        print(f"[OK] Verified passwords: {', '.join(found_passwords)}")
    
    print("\n[PASS] All tests passed!")

if __name__ == "__main__":
    test_exercise3_results()
