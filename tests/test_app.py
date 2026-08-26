import os,tempfile
import pytest
from app import create_app
from app.monitor import check_tcp

@pytest.fixture
def client():
    fd,path=tempfile.mkstemp(suffix='.db');os.close(fd)
    app=create_app({'TESTING':True,'DB_PATH':path,'ADMIN_PASSWORD':'TestPassword!123','ADMIN_USERNAME':'admin','SECRET_KEY':'test-secret'})
    with app.test_client() as c: yield c
    os.unlink(path)

def login(c): return c.post('/login',data={'username':'admin','password':'TestPassword!123'})

def test_login_and_dashboard(client):
    assert login(client).status_code==302
    assert client.get('/').status_code==200

def test_bad_login(client):
    r=client.post('/login',data={'username':'admin','password':'wrong'})
    assert r.status_code==401

def test_api_requires_login(client):
    assert client.get('/api/overview').status_code==401

def test_create_target(client):
    login(client);r=client.post('/targets',json={'name':'Local','host':'127.0.0.1','port':5000})
    assert r.status_code==201
    assert b'Local' in client.get('/api/overview').data

def test_tcp_invalid_port():
    status,latency,error=check_tcp('127.0.0.1',0,0.1)
    assert status=='DOWN' and latency is None and error
