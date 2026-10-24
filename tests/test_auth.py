import requests
BASE = "https://trustvault-2059.onrender.com"

def test_idor_protection():
    r = requests.post(f"{BASE}/login", json={"username":"owner1","password":"owner123"})
    token_owner = r.json()["token"]
    
    r = requests.post(f"{BASE}/login", json={"username":"viewer1","password":"viewer123"})
    token_viewer = r.json()["token"]
    
    headers_owner = {"Authorization": f"Bearer {token_owner}"}
    r = requests.post(f"{BASE}/upload", headers=headers_owner, json={"name":"secret.pdf","content":"salary","category":"legal"})
    doc_id = r.json()["id"]
    
    headers_viewer = {"Authorization": f"Bearer {token_viewer}"}
    r = requests.get(f"{BASE}/documents/{doc_id}", headers=headers_viewer)
    assert r.status_code == 403
    print("PASS: 403 without grant")
    
    r = requests.post(f"{BASE}/grant", headers=headers_owner, json={"doc_id":doc_id,"username":"viewer1","permission":"read"})
    r = requests.get(f"{BASE}/documents/{doc_id}", headers=headers_viewer)
    assert r.status_code == 200
    print("PASS: 200 after grant - IDOR protected!")

if __name__ == "__main__":
    test_idor_protection()
