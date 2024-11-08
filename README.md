MQTT Secure Communication with ECC and AES
This project implements secure communication for MQTT clients using Elliptic Curve Cryptography (ECC) for key exchange and Advanced Encryption Standard (AES) for message encryption. The goal of this project is to enable secure data transmission in IoT systems using the MQTT protocol, ensuring that sensitive information is encrypted during transit.

Features

Elliptic Curve Cryptography (ECC) for secure key exchange.

AES Encryption to encrypt messages, ensuring confidentiality.

MQTT Integration for secure message exchange over MQTT.

Real-time decryption of messages using a shared secret derived from ECC key exchange.

Requirements
Python 3.x

paho-mqtt - MQTT library for Python.

pycryptodome - Python library for cryptographic operations like AES and ECC.


STEPS : 
1/ install the dependencies mentionned 
2/ generate pair keys for both client and server 
3/ run mosquitto
4/ start by running server side , forwarded by client side.
