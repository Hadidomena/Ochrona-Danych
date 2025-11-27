from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import sys, requests, base64, json, time

sys.path.append('./rsa_server_client_with_keys/rsa_server_client_with_keys/client')
from client import Client
client = Client('http://localhost:5555')

def task1_correct_encryption():
    public_key_pem = client.get_key('deadbeef')
    public_key = RSA.import_key(public_key_pem)
    message = b"Hello deadbeef, this is a secure message!"
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message)
    
    url = client.server_url + '/message/deadbeef'
    txt = base64.encodebytes(encrypted_message).decode()
    data = {'message': txt}
    response = requests.post(url, json=data)
    
    if response.status_code == 200:
        result = response.json()
        print(f"Correct: Decrypted response from deadbeef: {result['decrypted']}")
        return result['decrypted']
    else:
        raise Exception(f"FAIL({response.status_code}): {response.text}")

def task1_incorrect_encryption():
    wrong_key = RSA.generate(2048)
    message = b"This message is encrypted with wrong key!"
    cipher = PKCS1_OAEP.new(wrong_key.publickey())
    encrypted_message = cipher.encrypt(message)
    
    url = client.server_url + '/message/deadbeef'
    txt = base64.encodebytes(encrypted_message).decode()
    data = {'message': txt}
    response = requests.post(url, json=data)
    
    if response.status_code == 200:
        result = response.json()
        print(f"Incorrect: Unexpected success: {result}")
        return result
    else:
        print(f"Incorrect: Expected failure - {response.status_code}: {response.json().get('errors', response.text)}")
        return None


def task2a_bidirectional_communication(user1_id, user2_id):
    key1 = RSA.generate(2048)
    key2 = RSA.generate(2048)
    public_key1 = key1.publickey().export_key()
    public_key2 = key2.publickey().export_key()
    client.send_key(user1_id, public_key1)
    client.send_key(user2_id, public_key2)

    message1to2 = b"Hello from User1 to User2"
    public_key2 = RSA.import_key(client.get_key(user2_id))
    cipher = PKCS1_OAEP.new(public_key2)
    encrypted1to2 = cipher.encrypt(message1to2)
    client.send_binary_message(user2_id, encrypted1to2)
    
    received_encrypted = client.get_binary_message(user2_id)
    decipher = PKCS1_OAEP.new(key2)
    decrypted = decipher.decrypt(received_encrypted)
    print(f"User2 received: {decrypted.decode()}")
    
    message2to1 = b"Hello back from User2 to User1"
    public_key1 = RSA.import_key(client.get_key(user1_id))
    cipher = PKCS1_OAEP.new(public_key1)
    encrypted2to1 = cipher.encrypt(message2to1)
    client.send_binary_message(user1_id, encrypted2to1)
    
    received_encrypted = client.get_binary_message(user1_id)
    decipher = PKCS1_OAEP.new(key1)
    decrypted = decipher.decrypt(received_encrypted)
    print(f"User1 received: {decrypted.decode()}")


def task2b_signed_communication(user1_id, user2_id):
    key1 = RSA.generate(2048)
    key2 = RSA.generate(2048)
    public_key1 = key1.publickey().export_key()
    public_key2 = key2.publickey().export_key()
    client.send_key(user1_id, public_key1)
    client.send_key(user2_id, public_key2)
    
    message1to2 = b"Signed message from User1"
    hash_obj = SHA256.new(message1to2)
    signature = pkcs1_15.new(key1).sign(hash_obj)
    
    aes_key = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message1to2 + b'|||' + signature)
    
    pub_key2 = RSA.import_key(client.get_key(user2_id))
    cipher_rsa = PKCS1_OAEP.new(pub_key2)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    package = json.dumps({
        'encrypted_key': base64.b64encode(encrypted_aes_key).decode(),
        'nonce': base64.b64encode(cipher_aes.nonce).decode(),
        'tag': base64.b64encode(tag).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    })
    
    client.send_text_message(user2_id, package)
    
    received_package = client.get_text_message(user2_id)
    data = json.loads(received_package)
    
    encrypted_aes_key = base64.b64decode(data['encrypted_key'])
    nonce = base64.b64decode(data['nonce'])
    tag = base64.b64decode(data['tag'])
    ciphertext = base64.b64decode(data['ciphertext'])
    
    decipher_rsa = PKCS1_OAEP.new(key2)
    aes_key = decipher_rsa.decrypt(encrypted_aes_key)
    
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    parts = plaintext.split(b'|||')
    received_message = parts[0]
    received_signature = parts[1]
    
    pub_key1 = RSA.import_key(client.get_key(user1_id))
    hash_obj = SHA256.new(received_message)
    try:
        pkcs1_15.new(pub_key1).verify(hash_obj, received_signature)
        print(f"User2 received verified message: {received_message.decode()}")
    except (ValueError, TypeError):
        print("Signature verification FAILED")

def main():
    results = []
    tasks = input("Input tasks which should be done as name of tasks separated by spaces: ").split(" ")
    if "1" in tasks:
        print("\nTask 1: Send to deadbeef")
        start = time.time()
        try:
            print("Correct encryption")
            task1_correct_encryption()
            print("\nIncorrect encryption")
            task1_incorrect_encryption()
            t1 = time.time() - start
            results.append(f"Task 1: SUCCESS ({t1:.2f}s)")
        except Exception as e:
            results.append(f"Task 1: FAIL - {e}")
    
    if "2A" in tasks:
        print("\nTask 2A: Bidirectional communication")
        start = time.time()
        try:
            task2a_bidirectional_communication('alice', 'bob')
            t2a = time.time() - start
            results.append(f"Task 2A: SUCCESS ({t2a:.2f}s)")
        except Exception as e:
            results.append(f"Task 2A: FAIL - {e}")
    
    if "2B" in tasks:
        print("\nTask 2B: Signed communication")
        start = time.time()
        try:
            task2b_signed_communication('carol', 'dave')
            t2b = time.time() - start
            results.append(f"Task 2B: SUCCESS ({t2b:.2f}s)")
        except Exception as e:
            results.append(f"Task 2B: FAIL - {e}")
    
    with open("results.txt", "w") as f:
        f.write("\n".join(results))
    
    print("\nResults saved to results.txt")

if __name__ == "__main__":
    main()