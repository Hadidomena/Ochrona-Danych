import re

def test_exercise2_results():
    """Test exercise2 results from results.txt"""
    
    with open("results.txt", "r", encoding='utf-8') as f:
        content = f.read()
    
    print("=== Testing Exercise 2 Results ===\n")
    
    # Test Exercise 1
    assert "Exercise 1: Password Entropy" in content, "Exercise 1 section not found"
    
    time_match = re.search(r"Time: ([\d.]+)s", content)
    if time_match:
        ex1_time = float(time_match.group(1))
        print(f"[OK] Exercise 1 execution time: {ex1_time:.2f}s")
    
    if "55 characters" in content:
        print("[OK] Correct password length calculated (55 chars)")
    
    # Test Exercise 2
    assert "Exercise 2: AES-ECB Brute Force" in content, "Exercise 2 section not found"
    
    times = re.findall(r"Time: ([\d.]+)s", content)
    if len(times) >= 2:
        ex2_time = float(times[1])
        print(f"[OK] Exercise 2 execution time: {ex2_time:.2f}s")
    
    if "Key found:" in content:
        key_match = re.search(r"Key found: (\w+)", content)
        if key_match:
            key_char = key_match.group(1)
            print(f"[OK] Key found: {key_char}")
            assert len(key_char) == 1, "Key should be single character"
    
    if "Template attack" in content or "BMP header" in content:
        print("[OK] Attack method mentioned")
    
    # Test Advanced
    if "Advanced Attack" in content:
        print("[OK] Advanced attack section present")
        adv_times = re.findall(r"Time: ([\d.]+)s", content)
        if len(adv_times) >= 3:
            adv_time = float(adv_times[2])
            print(f"[OK] Advanced attack time: {adv_time:.2f}s")
    
    print("\n[PASS] All tests passed!")

if __name__ == "__main__":
    test_exercise2_results()
