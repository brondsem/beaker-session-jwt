from datetime import datetime, timedelta
from unittest.mock import MagicMock

from joserfc import jwt
from beaker.exceptions import BeakerException
from beaker.middleware import SessionMiddleware
from joserfc.errors import BadSignatureError
from webtest import TestApp
import pytest

from beaker_session_jwt import JWTCookieSession

jwt_secret1_bson_date = ('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.'
                         'eyJic1oiOiJjLWorWVV8YF9QTmh-ZzVVXnVaTHRDYlBSMXBwQFQxU3QifQ.'
                         'WEcBA2UIvQCsjy-qtDv9OmeurJEMFiXey-_cS6Hgni0')

# FakeReq = MagicMock
FakeReq = dict

def test_sign_json():
    req = FakeReq()
    jcs = JWTCookieSession(req,
                           jwt_secret_keys='secret1',
                           bson_compress_jwt_payload=False)
    assert (jcs._encrypt_data({'username': 'dave'})
            == 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImRhdmUifQ.'
               '1LXPSRNwqCxUK0MLbkh5fFgP8TpydsN8cQ2qyNU0as8')

def test_sign_removes_unneeded_fields():
    req = FakeReq()
    jcs = JWTCookieSession(req,
                           jwt_secret_keys='secret1',
                           bson_compress_jwt_payload=False)
    assert jcs._encrypt_data({'username': 'dave'}) == jcs._encrypt_data({'username': 'dave',
                                                                         '_domain': 'example.com',
                                                                         '_path': '/',
                                                                         '_expires': None})

def test_sign_json_badtype():
    req = FakeReq()
    jcs = JWTCookieSession(req,
                           jwt_secret_keys='secret1',
                           bson_compress_jwt_payload=False)
    with pytest.raises(TypeError):
        jcs._encrypt_data({'last': datetime.now()})


def test_sign_bson():
    req = FakeReq()
    jcs = JWTCookieSession(req,
                           jwt_secret_keys='secret1')
    assert jcs._encrypt_data({'last': datetime(2023, 1, 1)} == jwt_secret1_bson_date)

def test_verify_json():
    req = FakeReq()
    jcs = JWTCookieSession(req,
                           jwt_secret_keys='secret1',
                           bson_compress_jwt_payload=False)
    assert jcs._decrypt_data(
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImRhdmUifQ.'
        '1LXPSRNwqCxUK0MLbkh5fFgP8TpydsN8cQ2qyNU0as8') == {'username': 'dave'}

def test_verify_bson():
    req = FakeReq()
    jcs = JWTCookieSession(req,
                           jwt_secret_keys='secret1')
    assert jcs._decrypt_data(jwt_secret1_bson_date) == {'last': datetime(2023, 1, 1)}

def test_verify_secondary_key():
    req = FakeReq()
    jcs = JWTCookieSession(req,
                           jwt_secret_keys='newsecret, secret1')
    assert jcs._decrypt_data(jwt_secret1_bson_date) == {'last': datetime(2023, 1, 1)}

def test_verify_wrong_key():
    req = FakeReq()
    jcs = JWTCookieSession(req,
                           jwt_secret_keys='newsecret, othersecret')
    with pytest.raises(BadSignatureError):
        jcs._decrypt_data(jwt_secret1_bson_date)

def test_verify_no_signature():
    # a JWT vulnerability in the past was tokens that had "none" for signing algorithm
    # so could be easily crafted, so lets make sure they are not accepted
    req = FakeReq()
    jcs = JWTCookieSession(req,
                           jwt_secret_keys='secret1')
    jwt_no_sig = jwt.encode({'alg': 'none'}, {'user': 'admin'}, 'nosecret', algorithms=['none'])
    with pytest.raises(ValueError, match=r'^Algorithm of "none" is not allowed$'):
        jcs._decrypt_data(jwt_no_sig)

def test_verify_invalid():
    req = FakeReq()
    jcs = JWTCookieSession(req,
                           jwt_secret_keys='secret1')
    with pytest.raises(ValueError):
        jcs._decrypt_data('garbage')

def test_verify_original_format_invalid():
    req = FakeReq()
    jcs = JWTCookieSession(req,
                           jwt_secret_keys='secret1',
                           original_format_validate_key='oldsecret',
                           read_original_format=True)
    with pytest.raises(BeakerException, match=r'^Invalid original format signature$'):
        jcs._decrypt_data('asf')


def test_missing_configs():
    req = FakeReq()

    with pytest.raises(BeakerException, match=r'^No jwt_secret_keys specified$'):
        JWTCookieSession(req)

    with pytest.raises(BeakerException, match=r'^No original_format_validate_key specified$'):
        JWTCookieSession(req, jwt_secret_keys='x', read_original_format=True)

    # this was original behavior, not very meaningful to our implementation
    with pytest.raises(BeakerException, match=r'^timeout requires save_accessed_time$'):
        JWTCookieSession(req, jwt_secret_keys='x', timeout=5, save_accessed_time=False)

def test_bad_existing_cookie():
    req = FakeReq()
    req['cookie'] = '/bad/key=foo'
    jcs = JWTCookieSession(req, jwt_secret_keys='x')
    jcs._encrypt_data({'hi': 'you'})


def test_bad_cookie_value_with_session_cookie():
    req = FakeReq()
    req['cookie'] = 'foo={"bar":1,"a":"a"}; beaker.session.id=' + jwt_secret1_bson_date
    jcs = JWTCookieSession(req, jwt_secret_keys='secret1', timeout=10)
    assert 'last' in jcs


def test_bad_cookie_key_with_session_cookie():
    req = FakeReq()
    req['cookie'] = 'foo[1]=bar; beaker.session.id=' + jwt_secret1_bson_date
    jcs = JWTCookieSession(req, jwt_secret_keys='secret1', timeout=10)
    assert 'last' in jcs


def test_invalid_existing_cookie():
    req = FakeReq()
    req['cookie'] = 'beaker.session.id=/@?'
    JWTCookieSession(req, jwt_secret_keys='x', invalidate_corrupt=True)  # produces warning
    with pytest.raises(ValueError, match=r'^Invalid JSON Web Signature$'):
        JWTCookieSession(req, jwt_secret_keys='x', invalidate_corrupt=False)


def test_existing_cookie_timeout():
    # part of original class implementation, not too important to us
    req = FakeReq()
    req['cookie'] = f'beaker.session.id={jwt_secret1_bson_date}'
    jcs = JWTCookieSession(req, jwt_secret_keys='secret1', timeout=10)
    assert 'last' in jcs
    jcs = JWTCookieSession(req, jwt_secret_keys='secret1', timeout=-1)
    assert 'last' not in jcs


# derived from beaker/tests/test_cookie_only.py
def simple_app(environ, start_response):
    session = environ['beaker.session']
    if 'value' not in session:
        session['value'] = 0
    session['value'] += 1
    if not environ['PATH_INFO'].startswith('/skip-date'):
        session['example_date'] = datetime(2023, 5, 5)  # BSON can handle this.  JSON cannot
    if environ['PATH_INFO'].startswith('/add-timedelta'):
        session['example_delta'] = timedelta(33)  # only Pickle supports this
    session.save()
    start_response('200 OK', [('Content-type', 'text/plain')])
    msg = 'The current value is: %d and cookie is %s' % (session['value'], session)
    return [msg.encode('UTF-8')]


def test_full_app():
    options = {'session.jwt_secret_keys': 'secret1'}
    # `session_class` does trigger a deprecation warning, but 'session.class' key does not work
    app = TestApp(SessionMiddleware(simple_app,
                                    session_class=JWTCookieSession,
                                    **options))
    res = app.get('/')
    assert 'current value is: 1' in res.text
    res = app.get('/')
    assert 'current value is: 2' in res.text
    res = app.get('/')
    assert 'current value is: 3' in res.text


def test_sign_and_write_original_format():
    old_options = {
        'session.type': 'cookie',
        'session.validate_key': 'oldsecret',
    }
    old_app = TestApp(SessionMiddleware(simple_app,
                                        **old_options))
    new_options = {
        'session.jwt_secret_keys': 'secret1',
        'session.original_format_validate_key': 'oldsecret',
        'session.read_original_format': 'true',
        'session.write_original_format': 'true',
    }
    new_app = TestApp(SessionMiddleware(simple_app,
                                        session_class=JWTCookieSession,
                                        **new_options))

    # make sure new code produces a session that is still valid on old code
    resp = new_app.get('/')
    assert 'current value is: 1' in resp.text

    old_app.set_cookie('beaker.session.id', new_app.cookies['beaker.session.id'])
    resp = old_app.get('/')
    assert 'current value is: 2' in resp.text

    # and old is readable still by new
    new_app.set_cookie('beaker.session.id', old_app.cookies['beaker.session.id'])
    resp = new_app.get('/')
    assert 'current value is: 3' in resp.text


def test_upgrade_from_original_format():
    old_options = {
        'session.type': 'cookie',
        'session.validate_key': 'oldsecret',
    }
    old_app = TestApp(SessionMiddleware(simple_app,
                                        **old_options))
    new_options = {
        'session.jwt_secret_keys': 'secret1',
        'session.original_format_validate_key': 'oldsecret',
        'session.original_format_remove_keys': 'example_delta',
        'session.read_original_format': 'true',
        # 'session.write_original_format': 'true',
    }
    new_app = TestApp(SessionMiddleware(simple_app,
                                        session_class=JWTCookieSession,
                                        **new_options))

    resp = old_app.get('/add-timedelta')
    assert 'current value is: 1' in resp.text
    assert 'example_date' in resp.text
    assert 'example_delta' in resp.text

    new_app.set_cookie('beaker.session.id', old_app.cookies['beaker.session.id'])
    resp = new_app.get('/')
    assert 'current value is: 2' in resp.text
    assert 'example_date' in resp.text
    assert 'example_delta' not in resp.text  # because of original_format_remove_keys

    assert new_app.cookies['beaker.session.id'].startswith('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.')  # JWT format


def test_nonreserializable_is_logged(caplog):
    old_options = {
        'session.type': 'cookie',
        'session.validate_key': 'oldsecret',
        'session.invalidate_corrupt': 'true',
    }
    old_app = TestApp(SessionMiddleware(simple_app,
                                        **old_options))

    new_options = {
        'session.jwt_secret_keys': 'secret1',
        'session.original_format_validate_key': 'oldsecret',
        'session.read_original_format': 'true',
        'session.bson_compress_jwt_payload': 'false',  # to force serialization issue on 'example_date' entry
        'session.invalidate_corrupt': 'true',
    }
    new_app = TestApp(SessionMiddleware(simple_app,
                                        session_class=JWTCookieSession,
                                        **new_options))

    resp = old_app.get('/')
    assert 'current value is: 1' in resp.text
    new_app.set_cookie('beaker.session.id', old_app.cookies['beaker.session.id'])
    resp = new_app.get('/skip-date')  # load a page without re-adding it since that'll cause more problems
    assert 'original format cookie (pickle) loaded with fields that cannot be serialized' in caplog.records[0].message
    assert 'current value is: 1' in resp.text  # new session
