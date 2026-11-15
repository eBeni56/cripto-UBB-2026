from Crypto.Cipher import AES
import json
import base64

def AES128ENCODE(block, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)

def AES128DECODE(block, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)

def VIGENEREBINENCODE(plaintext, keyword):
    if not keyword:
            raise ValueError("Keyword must not be empty")
    save = keyword
    while len(keyword) < len(plaintext):
        keyword += save
    
    result = bytearray() #string helyett bytetomb
    for index, c in enumerate(plaintext):
        k = keyword[index]
        new_c = (c + k) % 256
        result.append(new_c)
    return bytes(result)

def VIGENEREBINDECODE(ciphertext, keyword):
    if not keyword:
            raise ValueError("Keyword must not be empty")
    save = keyword
    while len(keyword) < len(ciphertext):
        keyword += save
    
    result = bytearray()
    for index, c in enumerate(ciphertext):
        k = keyword[index]
        new_c = (c - k) % 256
        result.append(new_c)
    return bytes(result)

def pad(data, n, padding):
    if padding == "ZERO":
        maradek = len(data) % n
        if maradek == 0:
            return data
        return data + b"\x00" * (n - maradek)   #\x 16os szamrendszer
    elif padding == "DES":
        data = data + b"\x80"   #1000 0000 hozza adasa minden esetben
        maradek = len(data) % n
        if maradek == 0:
            return data
        return data + b"\x00" * (n - maradek)
    elif padding == "SF":
        hianyzo = n - (len(data) % n)   #hianyzo darab, hianyzo erteku bajttal egeszitjuk ki
        return data + bytes([hianyzo]) * hianyzo

    raise ValueError("Ismeretlen padding")

def unpad(data, n, padding):
    if padding == "ZERO":
        return data.rstrip(b"\x00") #rstrip - jobbrol torli addig az adott bajtot amig talal mast
    elif padding == "DES":
        stripped = data.rstrip(b"\x00")
        uj_hossz = len(stripped) - 1
        return stripped[0:uj_hossz]
    elif padding == "SF":
        utolso_index = len(data) - 1
        hianyzo = data[utolso_index]    #utolso bajt kiolvasasa
        uj_hossz = len(data) - hianyzo  #utolso bajtnyi bajt levagasa
        return data[0:uj_hossz]

    raise ValueError("Ismeretlen padding")

def xor_bytes(a, b):
    result = bytearray()
    for i in range(len(a)):
        result.append(a[i] ^ b[i])
    return bytes(result)

def inc_counter(counter):
    res = bytearray(counter)
    i = len(res) - 1
    while i >= 0:
        if res[i] < 255:
            res[i] += 1
            break
        res[i] = 0
        i -= 1
    return bytes(res)

def arrayEncoder(n, encode_func, key, mode, array, padding, iv=None):
    if mode != "ECB" and (iv is None or len(iv) != n):
        raise ValueError("ehhez a modhoz n bajt hosszu IV szukseges")

    padded = pad(array, n, padding)
    blocks = []
    for i in range(0, len(padded), n):
        blocks.append(padded[i:i + n])
    result = bytearray()

    if mode == "ECB":
        for p in blocks:
            c = encode_func(p, key)
            result.extend(c)
    elif mode == "CBC":
        prev = iv
        for p in blocks:
            xored = xor_bytes(p, prev)
            c = encode_func(xored, key)
            result.extend(c)
            prev = c
    elif mode == "CFB":
        prev = iv
        for p in blocks:
            kulcsfolyam = encode_func(prev, key)
            c = xor_bytes(kulcsfolyam, p)
            result.extend(c)
            prev = c
    elif mode == "OFB":
        o = iv
        for p in blocks:
            o = encode_func(o, key)
            c = xor_bytes(p, o)
            result.extend(c)
    elif mode == "CTR":
        counter = iv
        for p in blocks:
            kulcsfolyam = encode_func(counter, key)
            c = xor_bytes(p, kulcsfolyam)
            result.extend(c)
            counter = inc_counter(counter)
    else:
        raise ValueError("Ismeretlen mukodesi mod")

    return bytes(result)

def arrayDecoder(n, encode_func, decode_func, key, mode, array, padding, iv=None):
    if mode != "ECB" and (iv is None or len(iv) != n):
        raise ValueError("ehhez a modhoz n bajt hosszu IV szukseges")

    blocks = []
    for i in range(0, len(array), n):
        blocks.append(array[i:i + n])
    result = bytearray()

    if mode == "ECB":
        for c in blocks:
            p = decode_func(c, key)
            result.extend(p)
    elif mode == "CBC":
        prev = iv
        for c in blocks:
            dekodolt = decode_func(c, key)
            p = xor_bytes(dekodolt, prev)
            result.extend(p)
            prev = c
    elif mode == "CFB":
        prev = iv
        for c in blocks:
            kulcsfolyam = encode_func(prev, key)
            p = xor_bytes(kulcsfolyam, c)
            result.extend(p)
            prev = c
    elif mode == "OFB":
        o = iv
        for c in blocks:
            o = encode_func(o, key)
            p = xor_bytes(c, o)
            result.extend(p)
    elif mode == "CTR":
        counter = iv
        for c in blocks:
            kulcsfolyam = encode_func(counter, key)
            p = xor_bytes(c, kulcsfolyam)
            result.extend(p)
            counter = inc_counter(counter)
    else:
        raise ValueError("Ismeretlen mukodesi mod")

    return unpad(bytes(result), n, padding)

def configBetolt(json_fajlnev):
    f = open(json_fajlnev, "r", encoding="utf-8")
    cfg = json.load(f)
    f.close()

    n = cfg["blocksize"]
    mode = cfg["mode"]
    padding = cfg["padding"]
    key = base64.b64decode(cfg["key"])

    if "iv" in cfg:
        iv = base64.b64decode(cfg["iv"])
    else:
        iv = None

    if cfg["cipher"] == "VIGENERE-BIN":
        enc_func = VIGENEREBINENCODE
        dec_func = VIGENEREBINDECODE
    elif cfg["cipher"] == "AES-128":
        enc_func = AES128ENCODE
        dec_func = AES128DECODE
    else:
        raise ValueError("Ismeretlen algoritmus")

    return n, enc_func, dec_func, key, mode, padding, iv

def encodeWithConfig(array, json_fajlnev):
    n, enc_func, _, key, mode, padding, iv = configBetolt(json_fajlnev)
    return arrayEncoder(n, enc_func, key, mode, array, padding, iv)

def decodeWithConfig(array, json_fajlnev):
    n, enc_func, dec_func, key, mode, padding, iv = configBetolt(json_fajlnev)
    return arrayDecoder(n, enc_func, dec_func, key, mode, array, padding, iv)

def teszt(json_fajlnev):
    eredeti = b"ajfgp adfpausdh fuas fpaisue pfasdaf sefa espasi  APHS D asd awiD PI Wpdia "
    titkos = encodeWithConfig(eredeti, json_fajlnev)
    visszafejtett = decodeWithConfig(titkos, json_fajlnev)
    print(json_fajlnev, "-> Sikeres?", eredeti == visszafejtett)

if __name__ == "__main__":
    teszt("config_vigenere.json")
    teszt("config_aes.json")