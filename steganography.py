"""
SecureStego — Steganography Module
===================================
Implements Least Significant Bit (LSB) steganography on PNG images using Pillow.

Designed for MCA 3rd-Semester Cyber Security Academic Project.
Student Responsibility: Student 2 (Image Processing & Steganography Engine)
"""

import io
import struct
from typing import Tuple, Dict, Any, Union
from PIL import Image

# --- Configuration Constants ---
# 4-byte magic signature to identify SecureStego encoded images
MAGIC_HEADER = b"SSTE"
HEADER_LEN = len(MAGIC_HEADER)  # 4 bytes
LENGTH_FIELD_LEN = 4            # 4 bytes for unsigned 32-bit integer (>I)
METADATA_HEADER_BYTES = HEADER_LEN + LENGTH_FIELD_LEN  # 8 bytes total


class SteganographyError(Exception):
    """Base exception class for steganography errors."""
    pass


class CapacityError(SteganographyError):
    """Raised when the message payload exceeds image carrying capacity."""
    pass


def _bytes_to_bits(data: bytes) -> list:
    """
    Converts a sequence of bytes into a flat list of binary bits (0s and 1s).
    Bits are ordered most significant bit (MSB) to least significant bit (LSB).
    """
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: list) -> bytes:
    """
    Converts a list of binary bits (multiple of 8) into bytes.
    """
    byte_list = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i : i + 8]:
            byte = (byte << 1) | bit
        byte_list.append(byte)
    return bytes(byte_list)


def inspect_image(image_input: Union[str, bytes, io.BytesIO]) -> Tuple[Image.Image, Dict[str, Any]]:
    """
    Opens and validates an image from file path, bytes, or file-like object.
    Ensures the image is in PNG format and prepares it in RGB or RGBA mode.

    Returns:
        Tuple[Image.Image, Dict[str, Any]]: Pillow Image object and metadata dict.
    """
    try:
        if isinstance(image_input, bytes):
            image_stream = io.BytesIO(image_input)
        elif isinstance(image_input, str):
            image_stream = image_input
        else:
            image_stream = image_input

        img = Image.open(image_stream)

        # Validate that the actual image content format is PNG
        if img.format != "PNG":
            raise SteganographyError(
                f"Unsupported image format: '{img.format}'. Only PNG images are supported for lossless steganography."
            )

        # Convert to RGB or RGBA mode if indexed/grayscale
        if img.mode not in ("RGB", "RGBA"):
            img = img.convert("RGBA" if "transparency" in img.info else "RGB")

        width, height = img.size
        # Each pixel has 3 color channels available (R, G, B) - Alpha is left untouched
        available_bits = width * height * 3
        total_capacity_bytes = available_bits // 8
        max_payload_bytes = max(0, total_capacity_bytes - METADATA_HEADER_BYTES)

        metadata = {
            "width": width,
            "height": height,
            "mode": img.mode,
            "total_pixels": width * height,
            "total_capacity_bytes": total_capacity_bytes,
            "max_payload_bytes": max_payload_bytes,
        }
        return img, metadata

    except SteganographyError:
        raise
    except Exception as e:
        raise SteganographyError(f"Failed to process image file: {str(e)}")


def embed_payload(image_input: Union[str, bytes, io.BytesIO], payload: bytes) -> io.BytesIO:
    """
    Embeds an encrypted binary payload into the LSBs of the image's RGB channels.

    Packaging Structure:
    [ MAGIC (4B) ] + [ PAYLOAD LENGTH (4B) ] + [ PAYLOAD (N Bytes) ]

    LSB Embedding Method:
    - Each byte is converted to 8 bits.
    - Each pixel's R, G, and B channel values have their least significant bit (bit 0)
      cleared and replaced with the next message bit.
    - Alpha channel (transparency) is preserved unchanged to prevent visual artifacts.
    - Stops immediately after all bits are embedded, leaving remaining pixels untouched.

    Parameters:
        image_input: Image file path, raw bytes, or BytesIO object.
        payload (bytes): The encrypted data to hide.

    Returns:
        io.BytesIO: In-memory PNG image containing the hidden message.
    """
    if not isinstance(payload, (bytes, bytearray)) or len(payload) == 0:
        raise SteganographyError("Payload to embed cannot be empty.")

    img, metadata = inspect_image(image_input)
    width, height = metadata["width"], metadata["height"]
    max_payload = metadata["max_payload_bytes"]

    payload_length = len(payload)
    if payload_length > max_payload:
        raise CapacityError(
            f"Payload size ({payload_length:,} bytes) exceeds image capacity ({max_payload:,} bytes). "
            f"Please use a larger image or a shorter message."
        )

    # Construct the full binary data package
    # 4 bytes Magic 'SSTE' + 4 bytes Big-Endian unsigned integer length + payload
    header = MAGIC_HEADER + struct.pack(">I", payload_length)
    full_data = header + payload

    # Convert all bytes into a stream of bits
    bits_to_hide = _bytes_to_bits(full_data)
    total_bits = len(bits_to_hide)

    # Load pixel buffer for fast modification
    # Note: Copy image to ensure we don't alter cached input
    img_copy = img.copy()
    pixel_map = img_copy.load()

    bit_index = 0
    has_alpha = (img_copy.mode == "RGBA")

    for y in range(height):
        for x in range(width):
            if bit_index >= total_bits:
                break

            pixel = pixel_map[x, y]
            r, g, b = pixel[0], pixel[1], pixel[2]

            # Modify R channel LSB
            if bit_index < total_bits:
                r = (r & ~1) | bits_to_hide[bit_index]
                bit_index += 1

            # Modify G channel LSB
            if bit_index < total_bits:
                g = (g & ~1) | bits_to_hide[bit_index]
                bit_index += 1

            # Modify B channel LSB
            if bit_index < total_bits:
                b = (b & ~1) | bits_to_hide[bit_index]
                bit_index += 1

            if has_alpha:
                pixel_map[x, y] = (r, g, b, pixel[3])
            else:
                pixel_map[x, y] = (r, g, b)

        if bit_index >= total_bits:
            break

    # Save output image in lossless PNG format into an in-memory buffer
    output_buffer = io.BytesIO()
    img_copy.save(output_buffer, format="PNG")
    output_buffer.seek(0)
    return output_buffer


def extract_payload(image_input: Union[str, bytes, io.BytesIO]) -> bytes:
    """
    Extracts the hidden encrypted payload from an image's LSB channels.

    Extraction Workflow:
    1. Read the first 64 bits (8 bytes):
       - First 4 bytes must match MAGIC_HEADER (b"SSTE"). If not, image does not contain SecureStego data.
       - Next 4 bytes are unpacked as Big-Endian uint32 to determine payload length.
    2. Validate that the encoded length does not exceed maximum image capacity.
    3. Read exactly `payload_length * 8` subsequent bits from the image pixels.
    4. Reassemble the bits into bytes and return the payload.

    Parameters:
        image_input: Image file path, raw bytes, or BytesIO object.

    Returns:
        bytes: The extracted encrypted binary payload.

    Raises:
        SteganographyError: If no valid header is found or payload is corrupted.
    """
    img, metadata = inspect_image(image_input)
    width, height = metadata["width"], metadata["height"]
    pixel_map = img.load()

    # Step 1: Extract header bits (64 bits for magic + length)
    header_bits_needed = METADATA_HEADER_BYTES * 8  # 64 bits
    header_bits = []

    for y in range(height):
        for x in range(width):
            if len(header_bits) >= header_bits_needed:
                break
            pixel = pixel_map[x, y]
            # Extract LSB from R, G, B
            for channel in (pixel[0], pixel[1], pixel[2]):
                if len(header_bits) < header_bits_needed:
                    header_bits.append(channel & 1)
        if len(header_bits) >= header_bits_needed:
            break

    if len(header_bits) < header_bits_needed:
        raise SteganographyError("Image too small to contain a SecureStego header.")

    header_bytes = _bits_to_bytes(header_bits)
    magic = header_bytes[:HEADER_LEN]
    if magic != MAGIC_HEADER:
        raise SteganographyError(
            "No SecureStego hidden message found in this image. "
            "Please ensure the image was created using SecureStego and has not been compressed or altered."
        )

    # Step 2: Unpack and validate payload length
    payload_length = struct.unpack(">I", header_bytes[HEADER_LEN:])[0]
    max_payload = metadata["max_payload_bytes"]

    if payload_length <= 0 or payload_length > max_payload:
        raise SteganographyError(
            f"Invalid or corrupted hidden message header (payload length: {payload_length})."
        )

    # Step 3: Extract the payload bits
    total_bits_needed = (METADATA_HEADER_BYTES + payload_length) * 8
    all_bits = []

    for y in range(height):
        for x in range(width):
            if len(all_bits) >= total_bits_needed:
                break
            pixel = pixel_map[x, y]
            for channel in (pixel[0], pixel[1], pixel[2]):
                if len(all_bits) < total_bits_needed:
                    all_bits.append(channel & 1)
        if len(all_bits) >= total_bits_needed:
            break

    if len(all_bits) < total_bits_needed:
        raise SteganographyError(
            "Image was truncated or does not contain the complete hidden message."
        )

    # Extract only the payload bits (skipping the 64 header bits)
    payload_bits = all_bits[header_bits_needed:total_bits_needed]
    return _bits_to_bytes(payload_bits)
