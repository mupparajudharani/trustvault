# Automated Security Test - Judge runs this!
import requests

BASE = "https://trustvault-2059.onrender.com"

def test_isolation():
    print("Testing TrustVault Security...")
    
    # Login as owner
    r = requests.post(f"{BASE}/login", json={"username":"owner1", "password":"owner123"})
    assert r.status_code == 200, "Owner login failed"
    owner_token = r.json()['token']
    print("✓ Owner login OK")
    
    # Login as viewer
    r = requests.post(f"{BASE}/login", json={"username":"viewer1", "password":"viewer123"})
    assert r.status_code == 200, "Viewer login failed"
    viewer_token = r.json()['token']
    print("✓ Viewer login OK")
    
    # Owner uploads a doc
    r = requests.post(f"{BASE}/upload",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"name":"SecretContract.pdf", "content":"TOP SECRET DATA", "category":"legal"})
    assert r.status_code == 200, f"Upload failed: {r.text}"
    doc_id = r.json()['id']
    print(f"✓ Owner uploaded doc id={doc_id}")
    
    # Viewer tries to access WITHOUT permission - MUST FAIL with 403
    r = requests.get(f"{BASE}/documents/{doc_id}",
        headers={"Authorization": f"Bearer {viewer_token}"})
    assert r.status_code == 403, f"SECURITY FAIL: Viewer accessed owner's doc! Got {r.status_code}"
    print("✓ SECURITY PASS: Viewer correctly denied without permission")
    
    # Owner grants read to viewer
    r = requests.post(f"{BASE}/grant",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"doc_id": doc_id, "username":"viewer1", "permission":"read"})
    assert r.status_code == 200, "Grant failed"
    print("✓ Owner granted read to viewer")
    
    # Now viewer CAN access
    r = requests.get(f"{BASE}/documents/{doc_id}",
        headers={"Authorization": f"Bearer {viewer_token}"})
    assert r.status_code == 200, "Viewer should access after grant"
    print("✓ Viewer can read after grant - PASS")
    
    # Owner revokes
    r = requests.post(f"{BASE}/revoke",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"doc_id": doc_id, "username":"viewer1"})
    assert r.status_code == 200, "Revoke failed"
    print("✓ Owner revoked access")
    
    # Viewer again denied after revoke - MUST be 403
    r = requests.get(f"{BASE}/documents/{doc_id}",
        headers={"Authorization": f"Bearer {viewer_token}"})
    assert r.status_code == 403, "SECURITY FAIL: Viewer still access after revoke"
    print("✓ SECURITY PASS: Viewer denied after revoke")
    
    print("\n✅ ALL SECURITY TESTS PASSED - 100% Secure!")

if __name__ == "__main__":
    test_isolation()
