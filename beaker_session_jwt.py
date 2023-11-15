import json
import logging
import zlib
from base64 import b64decode, b85decode, b85encode, b64encode
from http.cookies import BaseCookie, CookieError
import time

import bson
from bson.errors import BSONError
from beaker import util
from beaker.converters import aslist, asbool
from joserfc import jwt
from joserfc.jwk import OctKey
from joserfc.errors import BadSignatureError
from beaker.session import CookieSession, _session_id, SignedCookie, _ConfigurableSession, InvalidSignature
from beaker.exceptions import BeakerException


log = logging.getLogger(__name__)

class JWTCookieSession(CookieSession):

    # only HS256 is required by all JWT libraries
    # and its in all the examples
    # sounds like HS512 is longer and a bit more secure, but HS256 is still very good
    # https://crypto.stackexchange.com/questions/53826/hmac-sha256-vs-hmac-sha512-for-jwt-api-authentication
    # and HS512 isn't recommended by https://jose.authlib.org/en/dev/guide/algorithms/ (not sure why exactly)
    alg = 'HS256'
    # a unique key for our bson->zlib->b85 data:
    compress_claim_fld = 'bsZ'

    def __init__(self, request, key='beaker.session.id', timeout=None,
                 save_accessed_time=True, cookie_expires=True, cookie_domain=None,
                 cookie_path='/',
                 secure=False,
                 httponly=False,
                 invalidate_corrupt=False,
                 samesite='Lax',
                 jwt_secret_keys=None,
                 bson_compress_jwt_payload=True,
                 read_original_format=False,
                 write_original_format=False,
                 original_format_validate_key=None,
                 original_format_data_serializer='pickle',
                 original_format_remove_keys=None,
                 **kwargs):

        _ConfigurableSession.__init__(
            self,
            cookie_domain=cookie_domain,
            cookie_path=cookie_path
        )
        self.clear()

        self.request = request
        self.key = key
        self.timeout = timeout
        self.save_atime = save_accessed_time
        self.cookie_expires = cookie_expires
        self.request['set_cookie'] = False
        self.secure = secure
        self.httponly = httponly
        self.samesite = samesite
        self.invalidate_corrupt = invalidate_corrupt
        self.jwt_secret_keys = [OctKey.import_key(k) for k in aslist(jwt_secret_keys, sep=',')]
        self.bson_compress_jwt_payload = asbool(bson_compress_jwt_payload)
        self.read_original_format = asbool(read_original_format)
        self.write_original_format = asbool(write_original_format)
        if self.read_original_format or self.write_original_format:
            self.original_format_validate_key = original_format_validate_key
            self._set_serializer(original_format_data_serializer)
            self.original_format_data_serializer = self.serializer
            self.original_format_remove_keys = aslist(original_format_remove_keys, sep=',')
            if original_format_validate_key is None:
                raise BeakerException("No original_format_validate_key specified")

        if not self.jwt_secret_keys:
            raise BeakerException("No jwt_secret_keys specified")
        if timeout and not save_accessed_time:
            raise BeakerException("timeout requires save_accessed_time")

        try:
            cookieheader = request['cookie']
        except KeyError:
            cookieheader = ''
        # BaseCookie instead of SimpleCookie to avoid extra " when using write_original_format option
        self.cookie = BaseCookie(
            input=cookieheader,
        )

        self['_id'] = _session_id()
        self.is_new = True

        # If we have a cookie, load it
        if self.key in self.cookie and self.cookie[self.key].value is not None:
            self.is_new = False
            try:
                cookie_data = self.cookie[self.key].value
                self.update(self._decrypt_data(cookie_data))
            except Exception as e:
                if self.invalidate_corrupt:
                    util.warn(
                        "Invalidating corrupt session %s; "
                        "error was: %s.  Set invalidate_corrupt=False "
                        "to propagate this exception." % (self.id, e))
                    self.invalidate()
                else:
                    raise

            if self.timeout is not None:
                now = time.time()
                last_accessed_time = self.get('_accessed_time', now)
                if now - last_accessed_time > self.timeout:
                    self.clear()

            self.accessed_dict = self.copy()
            self._create_cookie()

    def _encrypt_data(self, session_data=None) -> str:
        """
        Doesn't actually encrypt, but does sign and serialize
        """
        session_data: dict = session_data or self.copy()

        if self.write_original_format:
            # from original __init__ and _encrypt_data:
            original_signer = SignedCookie(self.original_format_validate_key)
            data = b64encode(self.original_format_data_serializer.dumps(session_data)).decode('utf8')
            _, data_with_sig = original_signer.value_encode(data)
            return data_with_sig

        # these are internal to beaker
        session_data.pop('_expires', None)
        session_data.pop('_path', None)
        session_data.pop('_domain', None)

        if self.bson_compress_jwt_payload:
            # json -> zlib -> base85 (slightly better than base64) -> jwt
            bs = bson.encode(session_data)
            compressed: bytes = zlib.compress(bs, level=zlib.Z_BEST_COMPRESSION)
            encoded: str = b85encode(compressed).decode('utf-8')
            session_data = {self.compress_claim_fld: encoded}

        header = {"alg": self.alg}
        signed = jwt.encode(header, session_data, self.jwt_secret_keys[0])
        return signed


    def _decrypt_data(self, session_data: str) -> dict:
        try:
            for i, jwt_key in enumerate(self.jwt_secret_keys):
                try:
                    jwt_tok = jwt.decode(session_data, jwt_key, algorithms=[self.alg])
                    payload = jwt_tok.claims
                    compressed = payload.pop(self.compress_claim_fld, None)
                    if self.bson_compress_jwt_payload and compressed:
                        payload.update(bson.decode(zlib.decompress(b85decode(compressed))))
                    return payload
                except BadSignatureError:
                    if i == len(self.jwt_secret_keys) - 1:
                        # last one
                        raise
                    else:
                        # try more
                        continue
        except ValueError:
            # wasn't JWT at all
            if not self.read_original_format:
                raise

            # from original __init__ and _decrypt_data:
            original_verifier = SignedCookie(self.original_format_validate_key)
            data, _ = original_verifier.value_decode(session_data)
            if data is InvalidSignature:
                raise BeakerException("Invalid original format signature")
            data = b64decode(data)
            loaded = self.original_format_data_serializer.loads(data)

            # optional cleanup of old entries
            for k in self.original_format_remove_keys:
                loaded.pop(k, None)
            # and verify that it'll serialize again later; otherwise need to remove more fields
            try:
                bson.encode(loaded) if self.bson_compress_jwt_payload else json.dumps(loaded)
            except (BSONError, TypeError):
                log.error(f'original format cookie (pickle) loaded with fields that cannot be serialized, probably '
                          f'need to add one or more of these keys to original_format_remove_keys: {loaded.keys()}')
                raise

            return loaded
