import codecs
import hashlib
import ecdsa
import secrets
import requests
import json

def private_to_public(private_key):
    private_key_bytes = codecs.decode(private_key, 'hex')
    # Get ECDSA public key
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex')
    # Add bitcoin byte
    bitcoin_byte = b'04'
    public_key = bitcoin_byte + key_hex
    return public_key

def public_to_address(public_key):
    public_key_bytes = codecs.decode(public_key, 'hex')
    # Run SHA256 for the public key
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    # Run ripemd160 for the SHA256
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
    # Add network byte
    network_byte = b'00'
    network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
    network_bitcoin_public_key_bytes = codecs.decode(network_bitcoin_public_key, 'hex')
    # Double SHA256 to get checksum
    sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
    sha256_nbpk_digest = sha256_nbpk.digest()
    sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
    sha256_2_nbpk_digest = sha256_2_nbpk.digest()
    sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
    checksum = sha256_2_hex[:8]
    # Concatenate public key and checksum to get the address
    address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
    wallet = base58(address_hex)
    return wallet

def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros and convert hex to decimal
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add '1' for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string

def hex_to_wip(private_key):
    private_key='80'+ private_key+'01'
    bits = codecs.decode(private_key,'hex')
    hashed256=hashlib.sha256(bits).digest()
    hashed256=hashlib.sha256(hashed256).digest()
    hashed256=codecs.encode(hashed256,'hex')
    hashed256=hashed256.decode('utf-8')
    hashed256=list(hashed256)
    checksum=''
    for i in range(0,8):
        checksum=checksum+str(hashed256[i])
    private_key=private_key+checksum
    private_key=base58(private_key)
    return private_key

def generate_bitcoin_address():
    private_key_in_bits=secrets.randbits(256)
    private_key_in_hex=hex(private_key_in_bits)
    private_key_in_bits=0
    private_key_in_hex=str(private_key_in_hex)[2:]
    private_key_in_wip=hex_to_wip(private_key_in_hex)
    public_key=private_to_public(private_key_in_hex)
    public_address=public_to_address(public_key)

    return public_address,private_key_in_wip

[public,private]=generate_bitcoin_address()

print(public)
print(private)



