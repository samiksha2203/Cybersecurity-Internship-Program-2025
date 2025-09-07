import hashlib
from PIL import Image

# ---------- HASH GENERATION ----------
def generate_hash(file_path, algo="sha256"):
    h = hashlib.new(algo)
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()

# ---------- EMBEDDING ----------
def embed_hash(cover_img, target_file, stego_img="stego.png"):
    hash_val = generate_hash(target_file)
    img = Image.open(cover_img)
    img = img.convert("RGB")
    pixels = img.load()

    binary_hash = ''.join(format(ord(c), '08b') for c in hash_val)
    data_index = 0

    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            if data_index < len(binary_hash):
                r = (r & ~1) | int(binary_hash[data_index])  # LSB encoding
                data_index += 1
            pixels[x, y] = (r, g, b)
            if data_index >= len(binary_hash):
                break
        if data_index >= len(binary_hash):
            break

    img.save(stego_img)
    print(f"[+] Hash embedded into {stego_img}")

# ---------- EXTRACTION ----------
def extract_hash(stego_img, hash_length=64):  # 64 chars for SHA256
    img = Image.open(stego_img)
    pixels = img.load()
    binary_hash = ""
    count = 0

    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            binary_hash += str(r & 1)
            if len(binary_hash) >= hash_length * 8:
                break
        if len(binary_hash) >= hash_length * 8:
            break

    hash_str = ''.join(chr(int(binary_hash[i:i+8], 2)) for i in range(0, len(binary_hash), 8))
    return hash_str

# ---------- VERIFICATION ----------
def verify(stego_img, target_file):
    extracted_hash = extract_hash(stego_img)
    current_hash = generate_hash(target_file)
    if extracted_hash == current_hash:
        print("[✅] File Integrity Verified")
    else:
        print("[❌] File Integrity Compromised!")
        print(f"Extracted: {extracted_hash}\nCurrent:   {current_hash}")

# ---------------- DEMO ----------------
if __name__ == "__main__":
    # Step 1: Embed
    embed_hash("cover.png", "report.pdf", "stego.png")

    # Step 2: Verify
    verify("stego.png", "report.pdf")
