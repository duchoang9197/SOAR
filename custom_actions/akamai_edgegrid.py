import hashlib
import hmac
import base64
import datetime
import uuid
import http.client
import json

def sign_and_send_request(method, path, body, client_token, client_secret, access_token, host):
    timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H:%M:%S+0000')
    nonce = str(uuid.uuid4())
    signing_key = hmac.new(client_secret.encode(), timestamp.encode(), hashlib.sha256).digest()
    signing_key_base64 = base64.b64encode(signing_key).decode()

    data_to_sign = '\t'.join([method.upper(), path, host.lower(), '', '', access_token, timestamp, nonce, body])
    signature = hmac.new(signing_key, data_to_sign.encode(), hashlib.sha256).digest()
    signature_base64 = base64.b64encode(signature).decode()

    auth_header = f'EG1-HMAC-SHA256 client_token={client_token};access_token={access_token};timestamp={timestamp};nonce={nonce};signature={signature_base64}'

    conn = http.client.HTTPSConnection(host)
    headers = {
        'Authorization': auth_header,
        'Content-Type': 'application/json',
        'Host': host
    }
    conn.request(method, path, body, headers)
    res = conn.getresponse()
    data = res.read()
    return {
        "status_code": res.status,
        "response": json.loads(data.decode("utf-8"))
    }
