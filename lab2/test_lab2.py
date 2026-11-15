from lab2 import (
    AES128ENCODE, AES128DECODE,
    VIGENEREBINENCODE, VIGENEREBINDECODE,
    arrayEncoder, arrayDecoder,
    encodeWithConfig, decodeWithConfig
)

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