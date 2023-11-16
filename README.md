A new signed-cookie implementation for [Beaker Sessions](https://github.com/bbangert/beaker)

# Features

- so much safer than default Pickle serialization
- serialize with BSON and compress, so more datatypes supported than JSON (optional)
- multiple keys, so you can rotate them
- stronger hash algorithm (SHA256)
- backwards compatible reads/writes with original pickle-based beaker session cookies
- JWT for signing (although not much else of JWT is implemented)

# Install

```
pip install 'beaker-session-jwt'
```

# Usage

See beaker docs for general implementation.  Specify using this class:

```
from beaker_session_jwt import JWTCookieSession

app = SessionMiddleware(app, config, session_class=JWTCookieSession)
```

# Additional config options

See Beaker docs for main config options, many of which apply to this class too.

- `jwt_secret_keys` required. One or more comma-separated keys
  - generate a key with `python -c 'import secrets; print(secrets.token_hex());'` 
  - multiple signing keys are supported, so you can rotate them.  The first one in the list will be used for writing, the rest will be permitted for verifying.
- `bson_compress_jwt_payload` default True
  - serializing with BSON and compressing with zlib, to allow for types like datetime, bytes, etc to be stored which JSON cannot store.  This is stored all in a single JWT field, so JWT is hardly being used, just for signatures really
- `read_original_format` default False
  - set to true to read original beaker signed cookies.  Allows for backward compatibility and transition periods
  - after a transition period, make sure to set this back to False
- `original_format_validate_key` required if `read_original_format`
- `original_format_data_serializer`
- `original_format_remove_keys` optional comma-separated list
  - if your old sessions have values that pickle supported, but don't work any more, list the session keys here.  They will be removed but the rest of the session will be preserved.
- `write_original_format` default False
  - set to true if you have many servers/processes and need to roll this out gradually.  Then later set to False when all processes are ready.

# Non-Features

- no encrypted cookies (could be possible with JWT though)
- JWT payload/claim fields (`iss`, `sub`, `exp`, etc) are not used or verified. Instead, this uses the fields that a beaker CookieSession has, for maximum backwards compatibility and simplicity.
- pymongo/bson is always required even with `bson_compress_jwt_payload=False`

# License

Apache License
