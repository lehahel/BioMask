import face_recognition
import numpy as np
import hashlib
import json
from reedsolo import RSCodec

EMBEDDING_LEN = 128
BIT_THRESHOLD = 0.0  # порог для бинаризации
RS_SYMBOLS = 16      # символы коррекции ошибок

def get_face_embedding(image_path: str) -> np.ndarray:
    img = face_recognition.load_image_file(image_path)
    encodings = face_recognition.face_encodings(img)
    if not encodings:
        raise ValueError("Лицо не найдено")
    return np.array(encodings[0])  # (128,)

def embedding_to_bits(embedding: np.ndarray, threshold=BIT_THRESHOLD) -> bytes:
    bits = (embedding > threshold).astype(np.uint8)  # 0 или 1
    bit_string = ''.join(str(b) for b in bits)
    return int(bit_string, 2).to_bytes((len(bit_string) + 7) // 8, byteorder='big')

def fuzzy_gen(image_path: str):
    emb = get_face_embedding(image_path)
    bit_bytes = embedding_to_bits(emb)

    rsc = RSCodec(RS_SYMBOLS)
    codeword = rsc.encode(bit_bytes)

    R = hashlib.sha256(bit_bytes).hexdigest()

    helper_data = list(codeword[len(bit_bytes):])  # tail (ECC part)
    return R, json.dumps({
        "rs_symbols": RS_SYMBOLS,
        "helper_data": helper_data
    })

def fuzzy_recover(image_path: str, p_json: str) -> str:
    data = json.loads(p_json)
    helper = bytes(data["helper_data"])
    rs_symbols = data["rs_symbols"]

    emb = get_face_embedding(image_path)
    bit_bytes = embedding_to_bits(emb)

    codeword = bit_bytes + helper
    rsc = RSCodec(rs_symbols)

    try:
        recovered, _, _ = rsc.decode(codeword)
    except:
        raise ValueError("❌ Слишком много ошибок — восстановление невозможно")

    return hashlib.sha256(bytes(recovered)).hexdigest()


if __name__ == "__main__":
    r, p = fuzzy_gen("image1.jpg")
    print(r)
    recovered_r = fuzzy_recover("image2.jpg", p)
    print(recovered_r)

