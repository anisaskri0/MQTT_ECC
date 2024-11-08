import json
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
import paho.mqtt.client as mqtt

# Function to decrypt the message using ECIES
def decrypt_message(encrypted_data):
    # Load server's private ECC key
    with open("server_private.pem", 'r') as f:
        server_private_key = ECC.import_key(f.read())
    
    # Load the ephemeral public key sent by the client
    ephemeral_public_key = ECC.import_key(encrypted_data['ephemeral_public_key'])
    
    # Compute shared secret using server's private key and client's ephemeral public key
    shared_secret = ephemeral_public_key.pointQ * server_private_key.d
    shared_secret_bytes = int(shared_secret.x).to_bytes(32, byteorder='big')

    # Derive AES key from shared secret
    aes_key = HKDF(master=shared_secret_bytes, key_len=16, hashmod=SHA256, salt=None, num_keys=1)

    # Decrypt the message using AES
    nonce = base64.b64decode(encrypted_data['nonce'])
    tag = base64.b64decode(encrypted_data['tag'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])

    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return decrypted_message.decode('utf-8')

# Callback when a message is received
def on_message(client, userdata, msg):
    encrypted_data = json.loads(msg.payload.decode())
    #(encrypted_data)
    decrypted_message = decrypt_message(encrypted_data)
    print(f"Decrypted message: {decrypted_message}")

# MQTT client setup
client = mqtt.Client()
client.on_message = on_message
client.connect("127.0.0.1", 1883, 60)
client.subscribe("test/topic")
client.loop_forever()
