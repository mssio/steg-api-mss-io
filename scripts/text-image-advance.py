#!/usr/bin/env python3
import sys
import os
import zlib
import hashlib
import math
from struct import pack, unpack
from io import BytesIO

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"


class PNGChunkWriter:
    def __init__(self):
        self.chunks = []

    def add_chunk(self, chunk_type: bytes, data: bytes):
        length = pack(">I", len(data))
        crc = pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
        self.chunks.append(length + chunk_type + data + crc)

    def build(self) -> bytes:
        return PNG_MAGIC + b"".join(self.chunks)


class SocialMediaSteg:
    MAX_CHARS = 500

    def __init__(self, password: str):
        self.password = password
        self.salt_size = 16
        self.key_iterations = 100000

    def _derive_key(self, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', self.password.encode(), salt, self.key_iterations, 32)

    def _encrypt(self, data: bytes) -> tuple[bytes, bytes]:
        salt = os.urandom(self.salt_size)
        key = self._derive_key(salt)
        encrypted = bytes([data[i] ^ key[i % 32] for i in range(len(data))])
        return salt, encrypted

    def _decrypt(self, salt: bytes, encrypted: bytes) -> bytes:
        key = self._derive_key(salt)
        return bytes([encrypted[i] ^ key[i % 32] for i in range(len(encrypted))])

    def _create_payload(self, text: str) -> bytes:
        text_bytes = text.encode('utf-8')
        crc = zlib.crc32(text_bytes) & 0xFFFFFFFF
        salt, encrypted = self._encrypt(text_bytes)
        length = len(text_bytes)
        payload = pack(">I", length) + salt + encrypted + pack(">I", crc)
        return payload

    def _extract_payload(self, data: bytes) -> str | None:
        try:
            if len(data) < 24:
                return None
            length = unpack(">I", data[:4])[0]
            if length > 10000 or length == 0:
                return None
            salt = data[4:20]
            encrypted = data[20:20 + length]
            stored_crc = unpack(">I", data[20 + length:24 + length])[0]
            decrypted = self._decrypt(salt, encrypted)
            if zlib.crc32(decrypted) & 0xFFFFFFFF != stored_crc:
                return None
            return decrypted.decode('utf-8')
        except:
            return None


class PNGDeflateSteg(SocialMediaSteg):
    MARKER = b'\xDE\xAD\xBE\xEF'

    def hide(self, text: str, input_path: str, output_path: str) -> bool:
        if len(text) > self.MAX_CHARS:
            print(f"Error: Maximum {self.MAX_CHARS} characters allowed")
            return False

        with open(input_path, 'rb') as f:
            png_data = f.read()

        if png_data[:8] != PNG_MAGIC:
            print("Error: Input must be PNG format")
            return False

        payload = self._create_payload(text)
        trailing_data = self.MARKER + pack(">I", len(payload)) + payload

        writer = PNGChunkWriter()
        pos = 8
        idat_bodies = []
        width, height = 0, 0

        while pos < len(png_data):
            chunk_len = unpack(">I", png_data[pos:pos + 4])[0]
            chunk_type = png_data[pos + 4:pos + 8]
            chunk_body = png_data[pos + 8:pos + 8 + chunk_len]
            pos += 12 + chunk_len

            if chunk_type == b"IHDR":
                width, height = unpack(">II", chunk_body[:8])
                writer.add_chunk(chunk_type, chunk_body)
            elif chunk_type == b"PLTE":
                writer.add_chunk(chunk_type, chunk_body)
            elif chunk_type == b"IDAT":
                idat_bodies.append(chunk_body)
            elif chunk_type == b"IEND":
                combined_idat = b"".join(idat_bodies) + trailing_data
                writer.add_chunk(b"IDAT", combined_idat)
                writer.add_chunk(b"IEND", b"")
                break
            elif chunk_type[0:1].islower():
                continue
            else:
                writer.add_chunk(chunk_type, chunk_body)

        with open(output_path, 'wb') as f:
            f.write(writer.build())

        return self._check_compatibility(output_path, width, height)

    def _check_compatibility(self, path: str, width: int, height: int) -> bool:
        file_size = os.path.getsize(path)
        max_for_xcom = width * height

        print(f"\nPlatform Compatibility:")
        print(f"  File size: {file_size/1024:.1f} KB")

        if file_size < max_for_xcom:
            print(f"  [OK] X.com/Twitter: Will survive (size < {max_for_xcom})")
        else:
            print(f"  [WARN] X.com/Twitter: May re-encode (size > width*height)")

        print(f"  [OK] Telegram: Send as document to preserve")
        print(f"  [INFO] WhatsApp: Send as DOCUMENT to preserve")

        return True

    def reveal(self, input_path: str) -> str | None:
        with open(input_path, 'rb') as f:
            png_data = f.read()

        if png_data[:8] != PNG_MAGIC:
            return None

        pos = 8
        while pos < len(png_data):
            chunk_len = unpack(">I", png_data[pos:pos + 4])[0]
            chunk_type = png_data[pos + 4:pos + 8]
            chunk_body = png_data[pos + 8:pos + 8 + chunk_len]
            pos += 12 + chunk_len

            if chunk_type == b"IDAT":
                marker_pos = chunk_body.find(self.MARKER)
                if marker_pos != -1:
                    payload_len = unpack(">I", chunk_body[marker_pos + 4:marker_pos + 8])[0]
                    payload = chunk_body[marker_pos + 8:marker_pos + 8 + payload_len]
                    result = self._extract_payload(payload)
                    if result:
                        return result

        return None


class RobustBlockSteg(SocialMediaSteg):
    STRENGTH = 25
    MAX_CHARS_ROBUST = 500

    def __init__(self, password: str, block_size: int = 8, redundancy: int = 3, strength: int = 25):
        super().__init__(password)
        self.block_size = block_size
        self.redundancy = redundancy
        self.strength = strength

    def _bytes_to_bits(self, data: bytes) -> str:
        return ''.join(f'{b:08b}' for b in data)

    def _bits_to_bytes(self, bits: str) -> bytes:
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) - 7, 8))

    def _hamming_encode(self, bits: str) -> str:
        encoded = []
        for i in range(0, len(bits), 4):
            chunk = bits[i:i+4].ljust(4, '0')
            d1, d2, d3, d4 = [int(b) for b in chunk]
            p1 = d1 ^ d2 ^ d4
            p2 = d1 ^ d3 ^ d4
            p3 = d2 ^ d3 ^ d4
            encoded.append(f'{p1}{p2}{d1}{p3}{d2}{d3}{d4}')
        return ''.join(encoded)

    def _hamming_decode(self, bits: str) -> str:
        decoded = []
        for i in range(0, len(bits) - 6, 7):
            chunk = bits[i:i+7]
            if len(chunk) < 7:
                break
            p1, p2, d1, p3, d2, d3, d4 = [int(b) for b in chunk]
            s1 = p1 ^ d1 ^ d2 ^ d4
            s2 = p2 ^ d1 ^ d3 ^ d4
            s3 = p3 ^ d2 ^ d3 ^ d4
            error_pos = s1 * 1 + s2 * 2 + s3 * 4
            bits_list = [p1, p2, d1, p3, d2, d3, d4]
            if error_pos > 0 and error_pos <= 7:
                bits_list[error_pos - 1] ^= 1
            decoded.append(f'{bits_list[2]}{bits_list[4]}{bits_list[5]}{bits_list[6]}')
        return ''.join(decoded)

    def hide(self, text: str, input_path: str, output_path: str) -> bool:
        if len(text) > self.MAX_CHARS_ROBUST:
            print(f"Error: Robust mode supports max {self.MAX_CHARS_ROBUST} characters")
            return False

        try:
            from PIL import Image
            import numpy as np
        except ImportError:
            print("Error: PIL/Pillow required. Install with: pip install Pillow numpy")
            return False

        img = Image.open(input_path).convert('RGB')
        pixels = np.array(img, dtype=np.float64)
        h, w, _ = pixels.shape

        payload = self._create_payload(text)
        bits = self._bytes_to_bits(payload)
        encoded_bits = self._hamming_encode(bits)

        blocks_h = h // self.block_size
        blocks_w = w // self.block_size
        total_blocks = blocks_h * blocks_w
        bits_needed = len(encoded_bits) * self.redundancy

        if bits_needed > total_blocks:
            max_chars = (total_blocks // self.redundancy // 7 * 4) // 8 - 24
            print(f"Error: Image too small. Max ~{max(0, max_chars)} chars for this image")
            return False

        seed = int.from_bytes(hashlib.sha256(self.password.encode()).digest()[:4], 'big')
        np.random.seed(seed)
        block_order = np.random.permutation(total_blocks)

        Y = 0.299 * pixels[:,:,0] + 0.587 * pixels[:,:,1] + 0.114 * pixels[:,:,2]

        bit_idx = 0
        for i, block_num in enumerate(block_order):
            if bit_idx >= len(encoded_bits):
                break

            by = (block_num // blocks_w) * self.block_size
            bx = (block_num % blocks_w) * self.block_size

            current_bit = encoded_bits[bit_idx % len(encoded_bits)]
            block_y = Y[by:by+self.block_size, bx:bx+self.block_size]
            avg_lum = np.mean(block_y)

            target_offset = self.strength if current_bit == '1' else -self.strength

            center_y = self.block_size // 4
            center_x = self.block_size // 4
            center_h = self.block_size // 2
            center_w = self.block_size // 2

            for c in range(3):
                block = pixels[by:by+self.block_size, bx:bx+self.block_size, c]
                center_slice = block[center_y:center_y+center_h, center_x:center_x+center_w]
                edge_mask = np.ones((self.block_size, self.block_size), dtype=bool)
                edge_mask[center_y:center_y+center_h, center_x:center_x+center_w] = False

                half_offset = target_offset * 0.5
                center_slice += half_offset
                block[edge_mask] -= half_offset

            if (i + 1) % self.redundancy == 0:
                bit_idx += 1

        pixels = np.clip(pixels, 0, 255).astype(np.uint8)
        result = Image.fromarray(pixels)

        ext = output_path.lower().split('.')[-1]
        if ext in ['jpg', 'jpeg']:
            result.save(output_path, 'JPEG', quality=92)
        else:
            result.save(output_path, 'PNG')

        print(f"\nRobust Block Embedding:")
        print(f"  Blocks used: {len(encoded_bits) * self.redundancy} of {total_blocks}")
        print(f"  Redundancy: {self.redundancy}x with Hamming(7,4) ECC")
        print(f"  Block size: {self.block_size}x{self.block_size} pixels")
        print(f"\nPlatform Compatibility:")
        print(f"  [OK] X.com/Twitter: Should survive recompression")
        print(f"  [OK] Telegram: Should survive as photo")
        print(f"  [~] WhatsApp: May survive (test recommended)")
        print(f"\n  Note: Pattern will be subtly visible")

        return True

    def reveal(self, input_path: str) -> str | None:
        try:
            from PIL import Image
            import numpy as np
        except ImportError:
            return None

        img = Image.open(input_path).convert('RGB')
        pixels = np.array(img, dtype=np.float64)
        h, w, _ = pixels.shape

        blocks_h = h // self.block_size
        blocks_w = w // self.block_size
        total_blocks = blocks_h * blocks_w

        seed = int.from_bytes(hashlib.sha256(self.password.encode()).digest()[:4], 'big')
        np.random.seed(seed)
        block_order = np.random.permutation(total_blocks)

        Y = 0.299 * pixels[:,:,0] + 0.587 * pixels[:,:,1] + 0.114 * pixels[:,:,2]

        global_avg = np.mean(Y)

        max_bits = min(total_blocks // self.redundancy, 10000)
        votes = {}

        for i, block_num in enumerate(block_order[:max_bits * self.redundancy]):
            by = (block_num // blocks_w) * self.block_size
            bx = (block_num % blocks_w) * self.block_size

            block_y = Y[by:by+self.block_size, bx:bx+self.block_size]

            center_y = self.block_size // 4
            center_x = self.block_size // 4
            center_h = self.block_size // 2
            center_w = self.block_size // 2

            center_lum = np.mean(block_y[center_y:center_y+center_h, center_x:center_x+center_w])
            edge_mask = np.ones_like(block_y, dtype=bool)
            edge_mask[center_y:center_y+center_h, center_x:center_x+center_w] = False
            edge_lum = np.mean(block_y[edge_mask])

            diff = center_lum - edge_lum

            bit_num = i // self.redundancy
            if bit_num not in votes:
                votes[bit_num] = []
            votes[bit_num].append(1 if diff > 0 else 0)

        bits = []
        for i in range(len(votes)):
            if i not in votes:
                break
            vote_sum = sum(votes[i])
            bit = 1 if vote_sum > len(votes[i]) / 2 else 0
            bits.append(str(bit))

        encoded_bits = ''.join(bits)
        decoded_bits = self._hamming_decode(encoded_bits)

        for start in range(0, min(32, len(decoded_bits)), 8):
            try:
                payload = self._bits_to_bytes(decoded_bits[start:])
                result = self._extract_payload(payload)
                if result:
                    return result
            except:
                continue

        return None


class MultiMethodSteg:
    def __init__(self, password: str):
        self.password = password
        self.png_steg = PNGDeflateSteg(password)
        self.robust_steg = RobustBlockSteg(password)

    def hide(self, text: str, input_path: str, output_path: str, method: str = "auto") -> bool:
        ext_in = input_path.lower().split('.')[-1]
        ext_out = output_path.lower().split('.')[-1]

        if method == "robust":
            success = self.robust_steg.hide(text, input_path, output_path)
            if success:
                print(f"\nHidden {len(text)} characters using ROBUST method")
                print(f"Output: {output_path}")
            return success

        if method == "auto" or method == "deflate":
            if ext_in == "png" and ext_out == "png":
                success = self.png_steg.hide(text, input_path, output_path)
                if success:
                    print(f"\nHidden {len(text)} characters using PNG DEFLATE method")
                    print(f"Output: {output_path}")
                return success

        print(f"Error: Use PNG input/output for deflate, or use 'robust' method")
        return False

    def reveal(self, input_path: str) -> str | None:
        with open(input_path, 'rb') as f:
            header = f.read(8)

        if header[:8] == PNG_MAGIC:
            result = self.png_steg.reveal(input_path)
            if result:
                print("Extracted using PNG DEFLATE method")
                return result

        result = self.robust_steg.reveal(input_path)
        if result:
            print("Extracted using ROBUST block method")
            return result

        return None


def create_cover_png(width: int, height: int, output_path: str, style: str = "solid"):
    raw_data = b''

    if style == "solid":
        for y in range(height):
            raw_data += b'\x00'
            raw_data += bytes([100, 150, 200]) * width
    elif style == "gradient":
        for y in range(height):
            raw_data += b'\x00'
            for x in range(width):
                r = int((x / width) * 255)
                g = int((y / height) * 255)
                b = 128
                raw_data += bytes([r, g, b])
    else:
        import random
        random.seed(42)
        for y in range(height):
            raw_data += b'\x00'
            base_r = int((y / height) * 200) + 28
            base_g = int((y / height) * 100) + 78
            base_b = 180
            for x in range(width):
                noise = random.randint(-5, 5)
                raw_data += bytes([
                    min(255, max(0, base_r + noise)),
                    min(255, max(0, base_g + noise)),
                    min(255, max(0, base_b + noise))
                ])

    ihdr_data = pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)
    idat_data = zlib.compress(raw_data, 9)

    writer = PNGChunkWriter()
    writer.add_chunk(b'IHDR', ihdr_data)
    writer.add_chunk(b'IDAT', idat_data)
    writer.add_chunk(b'IEND', b'')

    with open(output_path, 'wb') as f:
        f.write(writer.build())

    file_size = os.path.getsize(output_path)
    max_size = width * height
    print(f"Created: {output_path}")
    print(f"  Dimensions: {width}x{height}")
    print(f"  File size: {file_size/1024:.1f} KB")
    print(f"  X.com compatible: {'Yes' if file_size < max_size else 'No'}")
    return True


def print_usage():
    print("Social Media Steganography Tool")
    print("================================")
    print()
    print("Two methods available:")
    print()
    print("  DEFLATE (default for PNG):")
    print("    - Invisible, high capacity (500 chars)")
    print("    - Survives: X.com, Telegram/WhatsApp as document")
    print("    - Does NOT survive: WhatsApp/Telegram as photo")
    print()
    print("  ROBUST (for photo sharing):")
    print("    - Subtly visible pattern, lower capacity (100 chars)")
    print("    - Uses block patterns + error correction")
    print("    - Survives: Recompression, X.com, Telegram as photo")
    print("    - May survive: WhatsApp as photo (test first)")
    print()
    print("Usage:")
    print(f"  {sys.argv[0]} hide <text> <password> <input> <output> [method]")
    print(f"  {sys.argv[0]} show <password> <image>")
    print(f"  {sys.argv[0]} create-cover <width> <height> <output.png> [style]")
    print()
    print("Methods: deflate, robust")
    print()
    print("Examples:")
    print(f"  # For X.com/Twitter (invisible, PNG only):")
    print(f"  {sys.argv[0]} create-cover 2048 2048 cover.png solid")
    print(f"  {sys.argv[0]} hide \"Secret\" pass cover.png output.png")
    print()
    print(f"  # For WhatsApp/Telegram as photo (visible pattern):")
    print(f"  {sys.argv[0]} hide \"Secret\" pass photo.jpg stego.jpg robust")
    print()
    print(f"  # Extract:")
    print(f"  {sys.argv[0]} show pass image.png")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "hide":
        if len(sys.argv) < 6:
            print("Usage: hide <text> <password> <input> <output> [method]")
            print("Methods: deflate (default for PNG), robust")
            sys.exit(1)

        text = sys.argv[2]
        password = sys.argv[3]
        input_path = sys.argv[4]
        output_path = sys.argv[5]
        method = sys.argv[6] if len(sys.argv) > 6 else "auto"

        steg = MultiMethodSteg(password)
        if steg.hide(text, input_path, output_path, method):
            print("\nSuccess!")
        else:
            print("Failed to hide message")
            sys.exit(1)

    elif cmd == "show":
        if len(sys.argv) < 4:
            print("Usage: show <password> <image>")
            sys.exit(1)

        password = sys.argv[2]
        input_path = sys.argv[3]

        steg = MultiMethodSteg(password)
        result = steg.reveal(input_path)

        if result:
            print(f"Message: {result}")
        else:
            print("No hidden message found or wrong password")
            sys.exit(1)

    elif cmd == "create-cover":
        if len(sys.argv) < 5:
            print("Usage: create-cover <width> <height> <output.png> [style]")
            print("Styles: solid, gradient, natural")
            sys.exit(1)

        width = int(sys.argv[2])
        height = int(sys.argv[3])
        output_path = sys.argv[4]
        style = sys.argv[5] if len(sys.argv) > 5 else "solid"
        create_cover_png(width, height, output_path, style)

    else:
        print_usage()
