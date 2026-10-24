import requests
BASE = "https://trustvault-2059.onrender.com"

def test_idor_protection():
    # Ensure users
    for u,p,r in [("owner1","owner123","owner"),("viewer1","viewer123","viewer")]:
        requests.post(f"{BASE}/register", json={"username":u,"password":p,"role":r})

    r = requests.post(f"{BASE}/login", json={"username":"owner1","password":"owner123"})
    token_owner = r.json()["token"]

    r = requests.post(f"{BASE}/login", json={"username":"viewer1","password":"viewer123"})
    token_viewer = r.json()["token"]

    headers_owner = {"Authorization": f"Bearer {token_owner}"}
    # FIXED: /documents not /upload
    r = requests.post(f"{BASE}/documents", headers=headers_owner, json={"name":"secret.pdf","content":"salary","category":"legal"})
    assert r.status_code == 201, f"Upload fail {r.text}"
    doc_id = r.json()["doc_id"]  # FIXED: doc_id not id

    headers_viewer = {"Authorization": f"Bearer {token_viewer}"}
    r = requests.get(f"{BASE}/documents/{doc_id}", headers=headers_viewer)
    assert r.status_code == 403
    print("PASS: 403 without grant")

    # FIXED: /documents/{id}/grant
    r = requests.post(f"{BASE}/documents/{doc_id}/grant", headers=headers_owner, json={"username":"viewer1"})
    assert r.status_code == 200, f"Grant fail {r.text}"
    r = requests.get(f"{BASE}/documents/{doc_id}", headers=headers_viewer)
    assert r.status_code == 200
    print("PASS: 200 after grant - IDOR protected!")

    # Extra: Test revoke too
    r = requests.post(f"{BASE}/documents/{doc_id}/revoke", headers=headers_owner, json={"username":"viewer1"})
    r = requests.get(f"{BASE}/documents/{doc_id}", headers=headers_viewer)
    assert r.status_code == 403
    print("PASS: 403 after revoke - IDOR protected!")

if __name__ == "__main__":
    test_idor_protection()
