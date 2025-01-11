import time
import os
import sys
import psutil  
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
    return dilithium_signature

def dilithium_verify(pub_key, message, signature):
    Dilithium2.verify(pub_key, message, signature)

def create_secret_cipher(kyber_public_key):
    shared_secret, cipher = encrypt_session_key(kyber_public_key)
    return shared_secret, cipher

def recovered_secret(kyber_private_key, cipher):
    recovered_secret = decrypt_session_key(kyber_private_key, cipher)
    return recovered_secret

def assert_secret(shared_secret, recovered_secret):
    assert shared_secret == recovered_secret, "Secrets do not match!"

# Function to monitor resource usage
def get_system_metrics():
    cpu_usage = psutil.cpu_percent(interval=None)
    memory_info = psutil.virtual_memory()
    memory_usage = memory_info.used / (1024 * 1024)  # Convert to MB
    return {"cpu_usage": cpu_usage, "memory_used": memory_usage}

def run_full_handshake(iterations: int):
    times = []
    for i in range(iterations):
        start = time.time()
        print(f"Iteration {i + 1}...")

        # Record system metrics before handshake
        metrics_before = get_system_metrics()

        # 1) Signature
        dilithium_keypair = Dilithium2.keygen()
        message = b"Hello PQC"
        signature = dilithium_signature(dilithium_private_key, message)
        dilithium_verify(dilithium_public_key, message, signature)
            
        # 2) KEM
        kyber_private_key, kyber_public_key = generate_kyber_keypair()
        ss_enc, ciphertext = create_secret_cipher(kyber_public_key)
        ss_dec = recovered_secret(kyber_private_key, ciphertext)
        assert_secret(ss_enc, ss_dec)

        # Record system metrics after handshake
        metrics_after = get_system_metrics()

        end = time.time()
        handshake_time = end - start
        times.append({
            "iteration": i + 1,
            "handshake_time_sec": handshake_time,
            "cpu_before": metrics_before["cpu_usage"],
            "cpu_after": metrics_after["cpu_usage"],
            "memory_before_mb": metrics_before["memory_used"],
            "memory_after_mb": metrics_after["memory_used"],
        })

    return times

# Save results to a specific folder
def save_results(folder_name, filename, results):
    os.makedirs(folder_name, exist_ok=True)
    file_path = os.path.join(folder_name, filename)
    with open(file_path, "w") as f:
        json.dump(results, f, indent=4)
    print(f"Results saved to {file_path}")

if __name__ == "__main__":
    NUM_ITER = 100
    handshake_times = run_full_handshake(NUM_ITER)

    results = {
        "iterations": NUM_ITER,
        "times": handshake_times
    }

    run_mode = os.getenv("RUN_MODE", "iot")
    if run_mode == "iot":
        save_results("iot_results", "iot_results.json", results)
    else:
        save_results("edge_results", "edge_results.json", results)
