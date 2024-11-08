from Crypto.PublicKey import ECC

# Generate the server's private key (ECC key pair)
server_private_key = ECC.generate(curve='P-256')

# Export the private key to a PEM file
with open("server_private.pem", "wt") as f:
    f.write(server_private_key.export_key(format='PEM'))

# Export the public key (corresponding to the private key)
server_public_key = server_private_key.public_key()
with open("server_public.pem", "wt") as f:
    f.write(server_public_key.export_key(format='PEM'))


# Generate the server's private key (ECC key pair)
server_private_key = ECC.generate(curve='P-256')

# Export the private key to a PEM file
with open("client_private.pem", "wt") as f:
    f.write(server_private_key.export_key(format='PEM'))

# Export the public key (corresponding to the private key)
server_public_key = server_private_key.public_key()
with open("client_public.pem", "wt") as f:
    f.write(server_public_key.export_key(format='PEM'))
print("Server keys (private and public) generated and saved.")
