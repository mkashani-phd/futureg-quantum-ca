import time
import numpy as np
import os
import sys
import csv

import json

# Add paths
sys.path.append(os.path.abspath(".."))
sys.path.append(os.path.join(os.getcwd(), 'dilithium/src'))

from dilithium_py.dilithium import Dilithium2

sys.path.append(os.path.join(os.getcwd(), 'pyky'))
sys.path.append(os.path.join(os.getcwd(), 'src'))

from src.key_management import generate_kyber_keypair, encrypt_session_key, decrypt_session_key

dilithium_keypair = Dilithium2.keygen()
dilithium_public_key, dilithium_private_key = dilithium_keypair


def dilithium_signature(dilithium_private_key, message):
    dilithium_signature = Dilithium2.sign(dilithium_private_key, message)
    # print(f" ***SIGNED*** with Signature Length: {len(dilithium_signature)} bytes")
    return dilithium_signature

def dilithium_verify(pub_key, message, signature):
    Dilithium2.verify(pub_key, message, signature)
    #     print(" ***VERIFIED*** successfully!")
    # else:
    #     print("***verification failed!***")

def create_secret_cipher(kyber_public_key):
    shared_secret, cipher = encrypt_session_key(kyber_public_key)
    # print(f"Shared Secret Length: {len(shared_secret)} bytes")
    # print(f"Cipher Length: {len(cipher)} bytes")
    return shared_secret, cipher

def recovered_secret(kyber_private_key, cipher):
    recovered_secret = decrypt_session_key(kyber_private_key, cipher)
    # print(f"Recovered Secret Length: {len(recovered_secret)} bytes")
    return recovered_secret

def assert_secret(shared_secret, recovered_secret):
    assert shared_secret == recovered_secret, "do not match!"
    # print(" matched!")

# print("Kyber shared secret **encapsulation and decapsulation**")

def run_full_handshake(iterations: int):
    times = []
    for i in range(iterations):
        start = time.time()
        print(f"{i + 1}...")
        # 1) Signature
        dilithium_keypair = Dilithium2.keygen()
        message = b"Hello PQC"
        signature = dilithium_signature(dilithium_private_key, message)
        
        dilithium_verify(dilithium_public_key, message, signature)
            
        # 2) KEM
        # Generate Kyber key pair
        kyber_private_key, kyber_public_key = generate_kyber_keypair()
        
        ss_enc, ciphertext = create_secret_cipher(kyber_public_key)
        ss_dec = recovered_secret(kyber_private_key, ciphertext)
        assert_secret(ss_enc, ss_dec)

        end = time.time()
        times.append((i + 1, end - start)) 
    return times


# Save results to a specific folder
def save_results(folder_name, filename, results):
    os.makedirs(folder_name, exist_ok=True)  # Create folder if it doesn't exist
    file_path = os.path.join(folder_name, filename)
    with open(file_path, "w") as f:
        json.dump(results, f)
    print(f"Results saved to {file_path}")


if __name__ == "__main__":
    NUM_ITER = 100
    handshake_times = run_full_handshake(NUM_ITER)
    # avg_time = np.mean(handshake_times)
    # std_time = np.std(handshake_times)


 # After running the handshake
results = {
    "iterations": NUM_ITER,
    # "avg_time": avg_time,
    # "std_time": std_time,
    "times": handshake_times
}

# Determine whether running for IoT or Edge based on env var
run_mode = os.getenv("RUN_MODE", "iot")
if run_mode == "iot":
    save_results("iot_results", "iot_results.json", results)
else:
    save_results("edge_results", "edge_results.json", results)