# This is most similar to bmbpy.py

import argparse
import requests
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import hashlib
import binascii
import ed25519
import time

API_URL = 'https://api.example.com'

def generate_keypair():
    response = requests.get(f'{API_URL}/keys')
    if response.status_code != 200:
        raise Exception(f'Failed to generate key pair: {response.text}')
    keys = response.json()
    private_key = RSA.importKey(keys['private'])
    public_key = RSA.importKey(keys['public'])
    return private_key, public_key

def sign_transaction(private_key, transaction):
    h = SHA256.new(str(transaction).encode('utf-8'))
    signer = PKCS1_v1_5.new(private_key)
    signature = signer.sign(h)
    return signature

def verify_transaction(public_key, transaction, signature):
    h = SHA256.new(str(transaction).encode('utf-8'))
    verifier = PKCS1_v1_5.new(public_key)
    return verifier.verify(h, signature)

def send_money(sender, recipient, amount):
    private_key, public_key = generate_keypair()
    transaction = {'sender': sender, 'recipient': recipient, 'amount': amount}
    signature = sign_transaction(private_key, transaction)
    payload = {'transaction': transaction, 'signature': signature}
    response = requests.post(f'{API_URL}/send', json=payload)
    if response.status_code != 200:
        raise Exception(f'Failed to send money: {response.text}')
    return response.json()

def create_wallet():
    private_key, public_key = generate_keypair()
    with open('wallet.txt', 'w') as f:
        f.write(f'{public_key.export_key().decode()},{private_key.export_key().decode()}')
    print(f'Created wallet with public key {public_key.export_key().decode()}')

def login():
    with open('wallet.txt', 'r') as f:
        public_key, private_key = f.read().strip().split(',')
    print(f'Logged in with public key {public_key}')
    return private_key



def big_to_little_endian(b):
    l = ""
    for i in range(0, len(b) // 2):
        l += b[len(b) - 1 - i * 2 - 1] + b[len(b) - 1 - i * 2]
    return l

def sign_tx(txhash, privkey):
    return privkey.sign(txhash, encoding="hex")

def generate_tx_content_hash(tx):
    ctx = hashlib.sha256()

    ctx.update(binascii.unhexlify(tx["to"]))
    ctx.update(binascii.unhexlify(tx["from"]))
    ctx.update(binascii.unhexlify(big_to_little_endian("{:016x}".format(int(tx["fee"])))))
    ctx.update(binascii.unhexlify(big_to_little_endian("{:016x}".format(int(tx["amount"])))))
    ctx.update(binascii.unhexlify(big_to_little_endian("{:016x}".format(int(tx["timestamp"])))))

    txc_hash = ctx.digest()

    return txc_hash


def generate_tx_hash(txchash, signature):
    return hashlib.sha256(txchash + binascii.unhexlify(signature)).hexdigest()


def generate_tx_hash_from_json(tx):
    return hashlib.sha256(generate_tx_content_hash(tx[0]) + binascii.unhexlify(tx[0]["signature"])).hexdigest()


def generate_tx_json(from_addr, to_addr, amount, fee, privkey):
    timestamp = round(time.time())
    txchash = generate_tx_content_hash({"from": from_addr, "to": to_addr, "fee": fee,
                                        "amount": amount, "timestamp": timestamp})
    signature = sign_tx(txchash, privkey).decode().upper()
    pubkeys = privkey.get_verifying_key().to_ascii(encoding="hex").decode().upper()
    tx_json = [{"amount": amount, "fee": fee, "from": from_addr,
                "signature": signature,
                "signingKey": pubkeys, "timestamp": str(timestamp),
                "to": to_addr}]

    return tx_json


def submit_tx_json(txjson, hosts):

    r = None
    for i, host in enumerate(hosts):

        url = 'http://{}:3000/add_transaction_json'.format(host)
        if i == 0:
            r = requests.post(url, json=txjson)
        else:
            requests.post(url, json=txjson)

    if r.text != '[{"status":"SUCCESS"}]':
        return False
    return True
