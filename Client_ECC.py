import json
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
import paho.mqtt.client as mqtt

# Function to encrypt the message using ECIES
def encrypt_message(message):
    try:
        # Generate ephemeral ECC key pair for the client
        client_key = ECC.generate(curve='P-256')
        
        # Load the server's public ECC key (assumed to be saved as PEM)
        with open("server_public.pem", 'r') as f:
            server_public_key = ECC.import_key(f.read())

        # Perform ECDH key exchange to generate the shared secret
        shared_secret = server_public_key.pointQ * client_key.d
        shared_secret_bytes = int(shared_secret.x).to_bytes(32, byteorder='big')

        # Derive AES key from shared secret's x-coordinate using HKDF
        aes_key = HKDF(shared_secret_bytes, key_len=16, hashmod=SHA256, salt=None, num_keys=1)

        # Encrypt the message using AES
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        nonce = cipher_aes.nonce
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())

        # Send ephemeral public key, nonce, tag, and ciphertext
        encrypted_data = {
            'ephemeral_public_key': client_key.public_key().export_key(format='PEM'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
        return encrypted_data
    except Exception as e:
        print(f"Error during encryption: {e}")
        return None

# Publish the encrypted message
def publish_message(client, message):
    encrypted_data = encrypt_message(message)
    if encrypted_data:
        encrypted_data_json = json.dumps(encrypted_data)
        client.publish("test/topic", encrypted_data_json)
        print("Message was published successfully!")
        #print("Encrypted message published:", encrypted_data_json)
    else:
        print("Failed to encrypt message.")

# MQTT client setup
client = mqtt.Client()
client.connect("127.0.0.1", 1883, 60)

# Publish a message
publish_message(client, "Message publishing test!")

# Gracefully disconnect after publishing
client.disconnect()
