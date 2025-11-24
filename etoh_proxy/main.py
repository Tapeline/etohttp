# Some vibecoded shit xD

import struct
import time
import os
import requests
from flask import Flask, request, Response
from io import BytesIO

app = Flask(__name__)

SECRET_KEY = os.environ.get("SECRET_KEY").encode("utf8")


# --- XTEA & CRYPTO HELPER (Same as before) ---
def xtea_encipher(num_rounds, v, key):
    y, z = v[0], v[1]
    sum_val = 0
    delta = 0x9E3779B9
    for _ in range(num_rounds):
        y = (y + ((((z << 4) ^ (z >> 5)) + z) ^ (
                sum_val + key[sum_val & 3]))) & 0xFFFFFFFF
        sum_val = (sum_val + delta) & 0xFFFFFFFF
        z = (z + ((((y << 4) ^ (y >> 5)) + y) ^ (
                sum_val + key[(sum_val >> 11) & 3]))) & 0xFFFFFFFF
    return [y, z]


def xtea_decipher(num_rounds, v, key):
    y, z = v[0], v[1]
    sum_val = (0x9E3779B9 * num_rounds) & 0xFFFFFFFF
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
        pad_len = 8 - (len(data) % 8)
        data += bytes([pad_len] * pad_len)

    output = bytearray()
    prev_block = list(struct.unpack(">2I", iv if iv else b'\x00' * 8))
    num_blocks = len(data) // 8

    for i in range(num_blocks):
        chunk = data[i * 8: (i + 1) * 8]
        curr_block = list(struct.unpack(">2I", chunk))
        if encrypt:
            curr_block[0] ^= prev_block[0]
            curr_block[1] ^= prev_block[1]
            processed = xtea_encipher(32, curr_block, k_parts)
            prev_block = processed
        else:
            processed = xtea_decipher(32, curr_block, k_parts)
            res_block = [processed[0] ^ prev_block[0],
                         processed[1] ^ prev_block[1]]
            prev_block = curr_block
            processed = res_block
        output.extend(struct.pack(">2I", *processed))

    if not encrypt:
        pad_len = output[-1]
        output = output[:-pad_len]
    return bytes(output)


# --- BINARY HELPERS (Java DataInput/Output Compatibility) ---
def read_utf(bio):
    # Reads Java's writeUTF(): 2 bytes length, then string
    length = struct.unpack(">H", bio.read(2))[0]
    return bio.read(length).decode('utf-8')


def write_utf(bio, string):
    data = string.encode('utf-8')
    bio.write(struct.pack(">H", len(data)))
    bio.write(data)


# --- PROXY LOGIC ---
@app.route('/gate', methods=['POST'])
def secure_gate():
    raw_data = request.get_data()
    if len(raw_data) < 8: return "Invalid", 400

    iv = raw_data[:8]
    ciphertext = raw_data[8:]

    try:
        plaintext_bytes = crypt_cbc(
            ciphertext, SECRET_KEY, encrypt=False, iv=iv
        )
        bio = BytesIO(plaintext_bytes)

        # 1. PARSE REQUEST (Binary)
        client_ts = struct.unpack(">Q", bio.read(8))[0]  # Read Long (8 bytes)
        method = read_utf(bio)
        url = read_utf(bio)

        header_count = struct.unpack(">I", bio.read(4))[0]  # Read Int
        headers = {}
        for _ in range(header_count):
            k = read_utf(bio)
            v = read_utf(bio)
            headers[k] = v

        body = read_utf(bio)

    except Exception as e:
        print(f"Decryption/Parsing failed: {e}")
        return "Bad Request", 400

    # Security Check
    if time.time() * 1000 - client_ts > 60000:
        return "Replay detected", 403

    # 2. FORWARD REQUEST
    print(f"Proxying {method} to {url}")
    try:
        resp = requests.request(method, url, headers=headers, data=body)
    except Exception as e:
        return f"Upstream Error: {e}", 502

    # 3. BUILD RESPONSE (Binary)
    # Format: [Status:Int] [Body:UTF]
    resp_bio = BytesIO()
    resp_bio.write(struct.pack(">I", resp.status_code))
    write_utf(resp_bio, resp.text)  # Assuming text body for simplicity

    # 4. ENCRYPT RESPONSE
    new_iv = os.urandom(8)
    encrypted_response = crypt_cbc(
        resp_bio.getvalue(), SECRET_KEY, encrypt=True, iv=new_iv
    )

    return Response(
        new_iv + encrypted_response, mimetype='application/octet-stream'
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 80)))
