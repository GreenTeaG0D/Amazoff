"""
Welcome to Bertie's BCrypt (BBCRYPT)
This implementation is split into several parts - this is because it can use either Blowfish or SHA-256 as its underlying hashing algorithm.
"""
#NOTE: Currently only hashing - no salting or key stretching - even though it may be vulnerable to dictionary attacks, rainbow tables, etc.
import base64
import hmac
import os

from DatabaseInterface import DatabaseInterface

BASE_DIR = os.path.dirname(__file__)
SHA_CONSTANTS_FILE = os.path.join(BASE_DIR, "hash_mix_constants.txt")
BLOWFISH_CONSTANTS_FILE = os.path.join(BASE_DIR, "blowfish_constants.txt")

with open(SHA_CONSTANTS_FILE, "r") as f:
    INITAL_HASH_VALUES = f.readline().split(',')
    MIX_CONSTANTS = f.readline().split(',')

_BLOWFISH_TABLE_CACHE = None

def sha256_hash(password):
    """
    Hashes a password using SHA-256.
    """
    def preprocess(message):
        msg = bytearray(message)
        bit_length = len(msg) * 8
        msg.append(0x80)
        while (len(msg) % 64) != 56:
            msg.append(0x00)
        msg += bit_length.to_bytes(8, "big")
        return msg

    def right_rotate(value, amount):
        amount &= 31
        return ((value >> amount) | (value << (32 - amount))) & 0xFFFFFFFF

    def prepare_words(chunk_bytes):
        words = [0] * 64
        for i in range(16):
            words[i] = int.from_bytes(chunk_bytes[i*4:(i+1)*4], "big")
        for i in range(16, 64):
            s0 = right_rotate(words[i-15], 7) ^ right_rotate(words[i-15], 18) ^ (words[i-15] >> 3)
            s1 = right_rotate(words[i-2], 17) ^ right_rotate(words[i-2], 19) ^ (words[i-2] >> 10)
            words[i] = (words[i-16] + s0 + words[i-7] + s1) & 0xFFFFFFFF
        return words

    if isinstance(password, str):
        message = password.encode("utf-8")
    elif isinstance(password, bytes):
        message = bytes(password)
    else:
        message = str(password).encode("utf-8")

    def parse_values(raw_values):
        parsed = []
        for value in raw_values:
            stripped = value.strip()
            if stripped:
                parsed.append(int(stripped, 16) & 0xFFFFFFFF)
        return parsed

    padded_message = preprocess(message)
    hash_values = parse_values(INITAL_HASH_VALUES)
    constants = parse_values(MIX_CONSTANTS)

    if len(hash_values) == 64 and len(constants) == 8:
        hash_values, constants = constants, hash_values

    for chunk_index in range(0, len(padded_message), 64):
        chunk = padded_message[chunk_index:chunk_index+64]
        schedule = prepare_words(chunk)
        a, b, c, d, e, f, g, h = hash_values

        for i in range(64):
            s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + s1 + ch + constants[i] + schedule[i]) & 0xFFFFFFFF
            s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        hash_values = [
            (hash_values[0] + a) & 0xFFFFFFFF,
            (hash_values[1] + b) & 0xFFFFFFFF,
            (hash_values[2] + c) & 0xFFFFFFFF,
            (hash_values[3] + d) & 0xFFFFFFFF,
            (hash_values[4] + e) & 0xFFFFFFFF,
            (hash_values[5] + f) & 0xFFFFFFFF,
            (hash_values[6] + g) & 0xFFFFFFFF,
            (hash_values[7] + h) & 0xFFFFFFFF,
        ]

    return "".join(f"{value:08x}" for value in hash_values)


def sha256_validate(plaintext, expected_hash):
    """
    Validates that the SHA-256 hash of the plaintext matches the expected hash.
    """
    if expected_hash is None:
        return False
    computed_hash = sha256_hash(plaintext)
    return hmac.compare_digest(computed_hash, expected_hash.lower())


# Blowfish helpers -----------------------------------------------------------

def _load_blowfish_tables():
    """
    Lazily loads Blowfish P-array/S-box data from disk rather than hard-coding it.
    Expected format: one comma-separated line for the P-array followed by four
    lines for the S-boxes, each expressed in hexadecimal.

    ! ATTRIBUTION: https://github.com/aluink/Blowfish/blob/master/constants.txt
    This file was used as the template for loading the Blowfish P-array and S-boxes from disk.
    """
    global _BLOWFISH_TABLE_CACHE
    if _BLOWFISH_TABLE_CACHE:
        return _BLOWFISH_TABLE_CACHE
    try:
        with open(BLOWFISH_CONSTANTS_FILE, "r") as fh:
            lines = [line.strip() for line in fh if line.strip()]
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"Missing Blowfish constants file at {BLOWFISH_CONSTANTS_FILE}"
        ) from exc

    if len(lines) < 5:
        raise ValueError("Blowfish constants file must contain at least five lines.")

    p_array = [int(value.strip(), 16) for value in lines[0].split(',') if value.strip()]
    s_boxes = [
        [int(value.strip(), 16) for value in lines[idx].split(',') if value.strip()]
        for idx in range(1, 5)
    ]

    _BLOWFISH_TABLE_CACHE = (p_array, s_boxes)
    return _BLOWFISH_TABLE_CACHE


def _blowfish_F(x, s_boxes):
    a = s_boxes[0][(x >> 24) & 0xFF]
    b = s_boxes[1][(x >> 16) & 0xFF]
    c = s_boxes[2][(x >> 8) & 0xFF]
    d = s_boxes[3][x & 0xFF]
    return ((a + b) ^ c) + d & 0xFFFFFFFF


def _blowfish_encrypt_block(left, right, p_array, s_boxes):
    for i in range(16):
        left ^= p_array[i]
        right ^= _blowfish_F(left, s_boxes)
        left, right = right, left
    left, right = right, left
    right ^= p_array[16]
    left ^= p_array[17]
    return left, right


def _blowfish_decrypt_block(left, right, p_array, s_boxes):
    for i in range(17, 1, -1):
        left ^= p_array[i]
        right ^= _blowfish_F(left, s_boxes)
        left, right = right, left
    left, right = right, left
    right ^= p_array[1]
    left ^= p_array[0]
    return left, right


def _expand_blowfish_key(key_bytes, base_p, base_s):
    if not key_bytes:
        raise ValueError("Blowfish key bytes must not be empty.")
    p_array = base_p[:]
    s_boxes = [row[:] for row in base_s]

    key_len = len(key_bytes)
    key_index = 0
    for i in range(len(p_array)):
        word = 0
        for _ in range(4):
            word = (word << 8) | key_bytes[key_index]
            key_index = (key_index + 1) % key_len
        p_array[i] ^= word

    left = right = 0
    for i in range(0, len(p_array), 2):
        left, right = _blowfish_encrypt_block(left, right, p_array, s_boxes)
        p_array[i], p_array[i + 1] = left, right

    for box in s_boxes:
        for i in range(0, len(box), 2):
            left, right = _blowfish_encrypt_block(left, right, p_array, s_boxes)
            box[i], box[i + 1] = left, right

    return p_array, s_boxes


def _pkcs7_pad(data, block_size=8):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data, block_size=8):
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid Blowfish ciphertext length.")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Corrupted PKCS#7 padding.")
    return data[:-pad_len]


def _xor(block_a, block_b):
    return bytes(a ^ b for a, b in zip(block_a, block_b))


def _blowfish_cbc_encrypt(data, key_bytes, iv):
    p_template, s_template = _load_blowfish_tables()
    p_array, s_boxes = _expand_blowfish_key(key_bytes, p_template, s_template)
    padded = _pkcs7_pad(data, 8)
    previous = iv
    encrypted = bytearray()

    for offset in range(0, len(padded), 8):
        block = _xor(padded[offset:offset+8], previous)
        left = int.from_bytes(block[:4], "big")
        right = int.from_bytes(block[4:], "big")
        left, right = _blowfish_encrypt_block(left, right, p_array, s_boxes)
        cipher_block = left.to_bytes(4, "big") + right.to_bytes(4, "big")
        encrypted.extend(cipher_block)
        previous = cipher_block

    return bytes(encrypted)


def _blowfish_cbc_decrypt(ciphertext, key_bytes, iv):
    if len(ciphertext) % 8 != 0:
        raise ValueError("Ciphertext must be a multiple of 8 bytes.")
    p_template, s_template = _load_blowfish_tables()
    p_array, s_boxes = _expand_blowfish_key(key_bytes, p_template, s_template)
    previous = iv
    decrypted = bytearray()

    for offset in range(0, len(ciphertext), 8):
        block = ciphertext[offset:offset+8]
        left = int.from_bytes(block[:4], "big")
        right = int.from_bytes(block[4:], "big")
        left, right = _blowfish_decrypt_block(left, right, p_array, s_boxes)
        plain_block = _xor(left.to_bytes(4, "big") + right.to_bytes(4, "big"), previous)
        decrypted.extend(plain_block)
        previous = block

    return _pkcs7_unpad(bytes(decrypted), 8)


def blowfish_encrypt(plaintext, key_label):
    """
    Uses Blowfish in CBC mode with PKCS#7 padding to keep the primitive simple
    while demonstrating proper IV/key hygiene: fresh random material is stored
    via `DatabaseInterface`, and the ciphertext bytes are surfaced as base64 so
    the rest of the stack can persist them easily.
    """
    if isinstance(plaintext, str):
        data = plaintext.encode("utf-8")
    elif isinstance(plaintext, bytes):
        data = bytes(plaintext)
    else:
        raise TypeError("Plaintext must be bytes or UTF-8 string.")

    key = os.urandom(16)
    iv = os.urandom(8)
    DatabaseInterface.store_blowfish_material(key_label, key.hex(), iv.hex())

    ciphertext = _blowfish_cbc_encrypt(data, key, iv)
    return base64.b64encode(ciphertext).decode("ascii")


def blowfish_decrypt(ciphertext_b64, key_label):
    """
    Complements `blowfish_encrypt`: it fetches the stored key/IV pair, decodes
    the base64 payload, runs CBC decryption + PKCS#7 removal, and returns the
    original plaintext bytes so callers can decide how to interpret them.
    """
    material = DatabaseInterface.fetch_blowfish_material(key_label)
    if isinstance(material, dict):
        key_hex = material.get("key_hex")
        iv_hex = material.get("iv_hex")
    else:
        key_hex, iv_hex = material

    if not key_hex or not iv_hex:
        raise ValueError("Blowfish material for label not found or incomplete.")

    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = _blowfish_cbc_decrypt(ciphertext, bytes.fromhex(key_hex), bytes.fromhex(iv_hex))
    return plaintext


if __name__ == "__main__":
    test_input = "abc"
    expected_output = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    result = sha256_hash(test_input)
    print(f"SHA-256('{test_input}') = {result}")
    if result == expected_output:
        print("Hash self-test passed.")
    else:
        print("Hash self-test failed!")

    validation_result = sha256_validate(test_input, expected_output)
    print(f"Validation self-test passed: {validation_result}")

    try:
        bf_cipher = blowfish_encrypt("demo", "demo-key")
        recovered = blowfish_decrypt(bf_cipher, "demo-key")
        print(f"Blowfish round-trip success: {recovered.decode('utf-8') == 'demo'}")
    except Exception as exc:
        print(f"Blowfish self-test skipped: {exc}")