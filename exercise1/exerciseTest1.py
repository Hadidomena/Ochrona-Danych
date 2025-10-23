import re

def test_exercise1_results():
    """Test exercise1 results from results.txt"""
    
    with open("results.txt", "r", encoding='utf-8') as f:
        content = f.read()
    
    print("=== Testing Exercise 1 Results ===\n")
    
    # Test Part 1
    assert "PART 1: Cyclical Cipher Analysis" in content, "Part 1 section not found"
    
    # Extract time for Part 1
    time_match = re.search(r"Time: ([\d.]+)s", content)
    if time_match:
        part1_time = float(time_match.group(1))
        print(f"[OK] Part 1 execution time: {part1_time:.2f}s")
        assert part1_time >= 0, "Invalid time"
    
    # Check for language results
    languages = ['english', 'french', 'polish']
    for lang in languages:
        if lang in content.lower():
            print(f"[OK] {lang.title()} results found")
    
    # Test Part 2
    assert "PART 2: RC4 Brute Force Analysis" in content, "Part 2 section not found"
    
    # Extract RC4 results
    part2_section = content.split("PART 2:")[1] if "PART 2:" in content else ""
    
    if "crypto.rc4" in part2_section:
        print("[OK] crypto.rc4 attack result found")
    
    if "crypto2.rc4" in part2_section:
        print("[OK] crypto2.rc4 attack result found")
    
    # Extract time for Part 2
    part2_time_match = re.findall(r"Time: ([\d.]+)s", content)
    if len(part2_time_match) >= 2:
        part2_time = float(part2_time_match[1])
        print(f"[OK] Part 2 execution time: {part2_time:.2f}s")
    
    # Check for keys
    if "key=" in content.lower():
        keys = re.findall(r"key=(\w+)", content.lower())
        for key in keys:
            if len(key) == 3:
                print(f"[OK] Found 3-char key: {key}")
    
    print("\n[PASS] All tests passed!")

if __name__ == "__main__":
    test_exercise1_results()
