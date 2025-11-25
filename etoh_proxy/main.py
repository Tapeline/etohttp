import struct
import time
import os
import secrets  # Available in Python 3.6+
import requests
from flask import Flask, request, Response
from io import BytesIO

app = Flask(__name__)

# --- CONFIGURATION ---
SERVER_N = int(os.getenv("ETOH_N"))
SERVER_D = int(os.getenv("ETOH_D"))
RSA_KEY_SIZE = 128
TUNNEL_LIFETIME = 3600 * 4  # 4 Hours

# Storage: { tunnel_id: { 'key': bytes, 'ts': timestamp } }
# In production, use Redis. Here, memory is fine.
SESSIONS = {}


# --- CRYPTO HELPERS (RSA & XTEA) ---
def rsa_decrypt_key(encrypted_bytes):
    c = int.from_bytes(encrypted_bytes, 'big')
    m = pow(c, SERVER_D, SERVER_N)
    padded = m.to_bytes(RSA_KEY_SIZE, 'big')
    # PKCS#1 v1.5 unpadding
    try:
        sep = padded.index(b'\x00', 2)
        return padded[sep + 1:]
    except ValueError:
        raise Exception("Padding Error")


def xtea_encipher(num_rounds, v, key):
    y, z = v[0], v[1];
    sum_val = 0;
    delta = 0x9E3779B9
    for _ in range(num_rounds):
        y = (y + ((((z << 4) ^ (z >> 5)) + z) ^ (
                sum_val + key[sum_val & 3]))) & 0xFFFFFFFF
        sum_val = (sum_val + delta) & 0xFFFFFFFF
        z = (z + ((((y << 4) ^ (y >> 5)) + y) ^ (
                sum_val + key[(sum_val >> 11) & 3]))) & 0xFFFFFFFF
    return [y, z]


def xtea_decipher(num_rounds, v, key):
    y, z = v[0], v[1];
    sum_val = (0x9E3779B9 * num_rounds) & 0xFFFFFFFF;
    delta = 0x9E3779B9
    for _ in range(num_rounds):
        z = (z - ((((y << 4) ^ (y >> 5)) + y) ^ (
                sum_val + key[(sum_val >> 11) & 3]))) & 0xFFFFFFFF
        sum_val = (sum_val - delta) & 0xFFFFFFFF
        y = (y - ((((z << 4) ^ (z >> 5)) + z) ^ (
                sum_val + key[sum_val & 3]))) & 0xFFFFFFFF
    return [y, z]


def crypt_cbc(data, key, encrypt=True, iv=None):
    k_parts = list(struct.unpack(">4I", key))
    if encrypt:
        pad_len = 8 - (len(data) % 8);
        data += bytes([pad_len] * pad_len)
    output = bytearray();
    prev_block = list(struct.unpack(">2I", iv if iv else b'\x00' * 8))
    for i in range(len(data) // 8):
        chunk = data[i * 8: (i + 1) * 8];
        curr_block = list(struct.unpack(">2I", chunk))
        if encrypt:
            curr_block[0] ^= prev_block[0];
            curr_block[1] ^= prev_block[1]
            processed = xtea_encipher(32, curr_block, k_parts);
            prev_block = processed
        else:
            processed = xtea_decipher(32, curr_block, k_parts)
            res_block = [processed[0] ^ prev_block[0],
                         processed[1] ^ prev_block[1]]
            prev_block = curr_block;
            processed = res_block
        output.extend(struct.pack(">2I", *processed))
    if not encrypt: output = output[:-output[-1]]
    return bytes(output)


# --- ROUTES ---

@app.route('/tunnel', methods=['POST'])
def create_tunnel():
    """ 
    Handshake: Accepts RSA encrypted session key. 
    Returns: Plain text Tunnel ID 
    """
    raw_data = request.get_data()
    if len(raw_data) != RSA_KEY_SIZE:
        return "Invalid Size", 400

    try:
        session_key = rsa_decrypt_key(raw_data)
        if len(session_key) != 16: raise Exception("Invalid Key Size")

        # Generate Tunnel ID
        tunnel_id = secrets.token_hex(8)  # 16 chars

        # Save Session
        SESSIONS[tunnel_id] = {
            'key': session_key,
            'ts': time.time()
        }

        print(f"Tunnel Created: {tunnel_id}")
        return tunnel_id, 200  # Plain text ID

    except Exception as e:
        print(f"Handshake failed: {e}")
        return "Handshake Failed", 400


@app.route('/gate/<tunnel_id>', methods=['POST'])
def gate(tunnel_id):
    """
    Data Transfer: Accepts XTEA encrypted payload.
    """
    session = SESSIONS.get(tunnel_id)

    # 1. Check Expiration / Existence
    if not session:
        return "Tunnel Not Found", 410  # 410 Gone = Client must recreate

    if time.time() - session['ts'] > TUNNEL_LIFETIME:
        del SESSIONS[tunnel_id]
        return "Tunnel Expired", 410

    raw_data = request.get_data()
    if len(raw_data) < 8: return "Invalid", 400

    iv = raw_data[:8]
    ciphertext = raw_data[8:]
    session_key = session['key']

    try:
        # 2. Decrypt
        plaintext = crypt_cbc(ciphertext, session_key, encrypt=False, iv=iv)
        bio = BytesIO(plaintext)

        # 3. Parse Binary Protocol
        req_ts = struct.unpack(">Q", bio.read(8))[0]  # Replay protection
        method = struct.unpack(">H", bio.read(2))[0]  # Len
        method = bio.read(method).decode('utf-8')

        url_len = struct.unpack(">H", bio.read(2))[0]
        url = bio.read(url_len).decode('utf-8')

        header_count = struct.unpack(">I", bio.read(4))[0]  # Read Int
        headers = {}
        for _ in range(header_count):
            k = read_utf(bio)
            v = read_utf(bio)
            headers[k] = v

        body_len = struct.unpack(">I", bio.read(4))[0]
        body = bio.read(body_len)

        # 4. Proxy Request
        resp = requests.request(method, url, data=body)

        # 5. Encrypt Response
        resp_bio = BytesIO()
        resp_bio.write(struct.pack(">I", resp.status_code))
        resp_text = resp.text.encode('utf-8')
        resp_bio.write(struct.pack(">H", len(resp_text)))
        resp_bio.write(resp_text)

        new_iv = os.urandom(8)
        enc_resp = crypt_cbc(
            resp_bio.getvalue(), session_key, encrypt=True, iv=new_iv
        )

        return Response(new_iv + enc_resp, mimetype='application/octet-stream')

    except Exception as e:
        print(f"Gate Error: {e}")
        return "Processing Error", 400


def read_utf(bio):
    length = struct.unpack(">H", bio.read(2))[0]
    return bio.read(length).decode('utf-8')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
