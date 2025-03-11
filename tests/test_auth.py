# tests/test_auth.py
def test_login_page(client):
    response = client.get('/login')
    assert response.status_code == 200

def test_register_page(client):
    response = client.get('/register')
    assert response.status_code == 200

def test_register_user(client):
    response = client.post('/register', data={
        'username': 'testuser',
        'password': 'testpass123'
    })
    assert response.status_code == 302  # Redirect after successful registration
