#!/usr/bin/env python3
"""Generate a simple FCAE VPN .ico file with blue background and white text."""
import struct

def create_icon(size):
    """Create a minimal BMP icon data for given size."""
    pixels = []
    for y in range(size):
        row = []
        for x in range(size):
            # Blue background (#1A3A5C)
            r, g, b = 0x1A, 0x3A, 0x5C
            # Simple "F" letter in center
            cx, cy = size // 2, size // 2
            lx, ly = x - cx, y - cy
            # Draw a simple cross/plus pattern
            if abs(lx) <= size//8 and abs(ly) <= size//3:
                r, g, b = 0xFF, 0xFF, 0xFF
            elif abs(ly) <= size//8 and lx >= -size//3 and lx <= 0:
                r, g, b = 0xFF, 0xFF, 0xFF
            elif abs(ly) <= size//8 and lx >= -size//3 and lx <= -size//6:
                r, g, b = 0xFF, 0xFF, 0xFF
            pixels.append((b, g, r))  # BMP order: BGR
    return pixels

def make_ico():
    sizes = [16, 32, 48]
    all_icons = []
    for sz in sizes:
        px = create_icon(sz)
        # AND mask (1bpp, all zeros = fully opaque)
        and_mask = bytes(sz * (sz // 8))
        # BMP info header (40 bytes)
        bmp = struct.pack('<IiiHHIIiiII',
            40,        # header size
            sz,        # width
            sz * 2,    # height (doubled for ICO format)
            1,         # planes
            32,        # bits per pixel
            0,         # compression
            0,         # image size (0 for uncompressed)
            0, 0,      # resolution
            0, 0       # colors
        )
        # Pixel data (BGRA, bottom-up)
        img_data = b''
        for y in range(sz - 1, -1, -1):
            for x in range(sz):
                b, g, r = px[y * sz + x]
                img_data += bytes([b, g, r, 0xFF])
        all_icons.append((sz, bmp + img_data + and_mask))

    # ICO header
    ico = struct.pack('<HHH', 0, 1, len(all_icons))
    data_offset = 6 + len(all_icons) * 16
    for sz, data in all_icons:
        ico += struct.pack('<BBBBHHII',
            sz, sz,           # width, height
            0,                # colors
            0,                # reserved
            1,                # planes
            32,               # bpp
            len(data),        # size
            data_offset       # offset
        )
        data_offset += len(data)
    for sz, data in all_icons:
        ico += data
    return ico

if __name__ == '__main__':
    ico = make_ico()
    with open('icon.ico', 'wb') as f:
        f.write(ico)
    print(f'Generated icon.ico ({len(ico)} bytes)')
