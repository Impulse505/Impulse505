import requests

sigP = 72057594037927931
h_orig = 0x00c0f995c413ce93 # known original hash

def sig_of(b):
    s = 0
    for c in b:
        s = (s * 256 + c) % sigP
    return s

modified = (
    '# Подтвержденный аттестат\n'
    'паспорт: "1337676769"\n'
    'оценки:\n'
    '  физика: 5\n'
    '  химия: 5\n'
    '  геометрия: 5\n'
).encode()

prefix = modified + b'\n# '
h_prefix = sig_of(prefix)
pow256_7 = pow(256, 7, sigP)

found_suffix = None

for pad in range(0x20, 0x80):
    h_eff = h_prefix
    for n in range(5000):
        target7 = (h_orig - h_eff * pow256_7) % sigP
        tb = target7.to_bytes(7, 'big')
        if all(0x20 <= b < 0x80 for b in tb):
            found_suffix = bytes([pad]) * n + tb
            break
        h_eff = (h_eff * 256 + pad) % sigP
    if found_suffix:
        break

payload = prefix + found_suffix

print(f"Generated Payload: \n{payload.decode('utf-8')}")

# r = requests.post("http://localhost:8080/submit", data={"attestat": payload})
# print(r.text)
