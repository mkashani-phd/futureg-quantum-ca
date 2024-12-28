from src.key_management import generate_kyber_keypair

# Generate Kyber key pair
private_key, public_key = generate_kyber_keypair()
print("Length of Private Key:", len(private_key))
print("Length of Public Key:", len(public_key))
