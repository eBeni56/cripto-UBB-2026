from lab2 import (
    AES128ENCODE, AES128DECODE,
    VIGENEREBINENCODE, VIGENEREBINDECODE,
    arrayEncoder, arrayDecoder,
    encodeWithConfig, decodeWithConfig
)

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad as lib_pad

def test_aes_egyezik_a_konyvtarral():
    with open("kep.jpg", "rb") as f:
        eredeti = f.read()
    kulcs = b"0123456789abcdef"
    iv = b"fedcba9876543210"

    sajat = arrayEncoder(16, AES128ENCODE, kulcs, "CBC", eredeti, "SF", iv)
    konyvtari = AES.new(kulcs, AES.MODE_CBC, iv=iv).encrypt(lib_pad(eredeti, 16))

    assert sajat == konyvtari

def test_vigenere_kep():
    with open("kep.jpg", "rb") as f:
        eredeti = f.read()

    kulcs = b"titkos12"
    iv = b"12345678"

    for mod in ["ECB", "CBC", "CFB", "OFB", "CTR"]:
        titkos = arrayEncoder(8, VIGENEREBINENCODE, kulcs, mod, eredeti, "SF", iv)
        visszafejtett = arrayDecoder(8, VIGENEREBINENCODE, VIGENEREBINDECODE, kulcs, mod, titkos, "SF", iv)
        assert visszafejtett == eredeti

def test_aes_kep():
    with open("kep.jpg", "rb") as f:
        eredeti = f.read()

    kulcs = b"0123456789abcdef"
    iv = b"fedcba9876543210"

    for mod in ["ECB", "CBC", "CFB", "OFB", "CTR"]:
        titkos = arrayEncoder(16, AES128ENCODE, kulcs, mod, eredeti, "SF", iv)
        visszafejtett = arrayDecoder(16, AES128ENCODE, AES128DECODE, kulcs, mod, titkos, "SF", iv)
        assert visszafejtett == eredeti

def test_paddingok():
    eredeti = b"teszt szoveg a paddingokhoz"
    for pad_mod in ["ZERO", "DES", "SF"]:
        titkos = arrayEncoder(8, VIGENEREBINENCODE, b"titkos12", "ECB", eredeti, pad_mod)
        visszafejtett = arrayDecoder(8, VIGENEREBINENCODE, VIGENEREBINDECODE, b"titkos12", "ECB", titkos, pad_mod)
        assert visszafejtett == eredeti

def test_json_konfigok():
    eredeti = b"teszt szoveg a json fajlokhoz"
    for fajl in ["config_vigenere.json", "config_aes.json"]:
        titkos = encodeWithConfig(eredeti, fajl)
        visszafejtett = decodeWithConfig(titkos, fajl)
        assert visszafejtett == eredeti

def test_correct_encrypt():
    with open("kep.jpg", "rb") as f:
        eredeti = f.read()
    kulcs = b"0123456789abcdef"
    iv = b"fedcba9876543210"

    padded = lib_pad(eredeti, 16)

    sajat = arrayEncoder(16, AES128ENCODE, kulcs, "ECB", eredeti, "SF", iv)
    konyvtari = AES.new(kulcs, AES.MODE_ECB).encrypt(padded)
    assert sajat == konyvtari

    sajat = arrayEncoder(16, AES128ENCODE, kulcs, "CBC", eredeti, "SF", iv)
    konyvtari = AES.new(kulcs, AES.MODE_CBC, iv=iv).encrypt(padded)
    assert sajat == konyvtari

    sajat = arrayEncoder(16, AES128ENCODE, kulcs, "CFB", eredeti, "SF", iv)
    konyvtari = AES.new(kulcs, AES.MODE_CFB, iv=iv, segment_size=128).encrypt(padded)
    assert sajat == konyvtari

    sajat = arrayEncoder(16, AES128ENCODE, kulcs, "OFB", eredeti, "SF", iv)
    konyvtari = AES.new(kulcs, AES.MODE_OFB, iv=iv).encrypt(padded)
    assert sajat == konyvtari

    sajat = arrayEncoder(16, AES128ENCODE, kulcs, "CTR", eredeti, "SF", iv)
    konyvtari = AES.new(kulcs, AES.MODE_CTR, nonce=b"", initial_value=iv).encrypt(padded)
    assert sajat == konyvtari