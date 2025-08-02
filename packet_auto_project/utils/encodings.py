import base64, base58, urllib.parse

def rot13(s):
    return s.translate(str.maketrans(
        "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",
        "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"
    ))

def all_encodings(keyword):
    try:
        return {
            "plain": keyword,
            "lower": keyword.lower(),
            "upper": keyword.upper(),
            "capitalized": keyword.capitalize(),
            "base64": base64.b64encode(keyword.encode()).decode(),
            "base32": base64.b32encode(keyword.encode()).decode(),
            "base58": base58.b58encode(keyword.encode()).decode(),
            "hex": keyword.encode().hex(),
            "rot13": rot13(keyword),
            "url": urllib.parse.quote(keyword),
            "utf16le": ''.join(f"{c}\x00" for c in keyword).encode().hex()
        }
    except Exception:
        return {}

def load_keywords():
    d = {}
    with open("keyword.txt", "r", encoding="utf-8") as f:
        for line in f:
            kw = line.strip()
            for method, val in all_encodings(kw).items():
                d[val.lower()] = (kw, method)
    return d
