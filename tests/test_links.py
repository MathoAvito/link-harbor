# tests/test_links.py
def test_add_link(client, auth):
    auth.login()
    response = client.post('/add', data={
        'title': 'Test Link',
        'url': 'https://example.com',
        'category': 'Test Category'
    })
    assert response.status_code == 302

def test_delete_link(client, auth):
    auth.login()
    # First add a link
    response = client.post('/add', data={
        'title': 'Test Link',
        'url': 'https://example.com'
    })
    # Then delete it
    response = client.get('/delete/1')
    assert response.status_code == 302
