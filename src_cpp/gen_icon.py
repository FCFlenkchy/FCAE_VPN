#!/usr/bin/env python3
"""Generate FCAE VPN icon: blue background (#1A3A5C) with white 'FCAE' text."""
import struct, zlib, sys, os

# 5x7 pixel font for F, C, A, E
FONT = {
    'F': [
        [1,1,1,1,0],
        [1,0,0,0,0],
        [1,0,0,0,0],
        [1,1,1,0,0],
        [1,0,0,0,0],
        [1,0,0,0,0],
        [1,0,0,0,0],
    ],
    'C': [
        [0,1,1,1,0],
        [1,0,0,0,1],
        [1,0,0,0,0],
        [1,0,0,0,0],
        [1,0,0,0,0],
        [1,0,0,0,1],
        [0,1,1,1,0],
    ],
    'A': [
        [0,1,1,1,0],
        [1,0,0,0,1],
        [1,0,0,0,1],
        [1,1,1,1,1],
        [1,0,0,0,1],
        [1,0,0,0,1],
        [1,0,0,0,1],
    ],
    'E': [
        [1,1,1,1,1],
        [1,0,0,0,0],
        [1,0,0,0,0],
        [1,1,1,0,0],
        [1,0,0,0,0],
        [1,0,0,0,0],
        [1,1,1,1,1],
    ],
}

def create_icon(size):
    bg = (0x1A, 0x3A, 0x5C)
    fg = (0xFF, 0xFF, 0xFF)
    pixels = []
    # Text is 4 chars * 5px wide + 3 gaps = 23px, 7px tall
    text_w, text_h = 23, 7
    scale = max(1, (size - 4) // max(text_w, text_h))
    tw, th = text_w * scale, text_h * scale
    ox = (size - tw) // 2
    oy = (size - th) // 2

    for y in range(size):
        for x in range(size):
            # Border circle approximation
            dx, dy = x - size//2, y - size//2
            dist = (dx*dx + dy*dy) ** 0.5
            if dist > size * 0.48:
                pixels.append((0x10, 0x28, 0x40))
                continue
            if dist > size * 0.44:
                pixels.append((0x22, 0x44, 0x66))
                continue

            # Check if pixel falls on text
            tx = x - ox
            ty = y - oy
            if 0 <= tx < tw and 0 <= ty < th:
                char_idx = tx // (5 * scale)
                px_in_char = tx % (5 * scale)
                py_in_char = ty % (1 * scale)  # scale maps 1 source px to `scale` screen px
                src_x = px_in_char // scale
                src_y = ty // scale
                if 0 <= src_x < 5 and 0 <= src_y < 7:
                    ch = 'FCAE'[char_idx] if char_idx < 4 else None
                    if ch and FONT[ch][src_y][src_x]:
                        pixels.append(fg)
                        continue
            pixels.append(bg)
    return pixels

def make_ico():
    sizes = [16, 32, 48]
    all_icons = []
    for sz in sizes:
        px = create_icon(sz)
        and_mask = bytes(sz * ((sz + 7) // 8))
        bmp = struct.pack('<IiiHHIIiiII', 40, sz, sz*2, 1, 32, 0, 0, 0, 0, 0, 0)
        img_data = b''
        for y in range(sz-1, -1, -1):
            for x in range(sz):
                r, g, b = px[y*sz+x]
                img_data += bytes([b, g, r, 0xFF])
        all_icons.append((sz, bmp + img_data + and_mask))
    ico = struct.pack('<HHH', 0, 1, len(all_icons))
    off = 6 + len(all_icons) * 16
    for sz, data in all_icons:
        ico += struct.pack('<BBBBHHII', sz, sz, 0, 0, 1, 32, len(data), off)
        off += len(data)
    for _, data in all_icons:
        ico += data
    return ico

def write_png(pixels, size, path):
    raw = b''
    for y in range(size):
        raw += b'\x00'
        for x in range(size):
            r, g, b = pixels[y*size+x]
            raw += bytes([r, g, b, 0xFF])
    def chunk(ct, d):
        c = ct + d
        return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xFFFFFFFF)
    ihdr = struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', ihdr) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'')

if __name__ == '__main__':
    ico_out = sys.argv[1] if len(sys.argv) > 1 else 'icon.ico'
    ico = make_ico()
    with open(ico_out, 'wb') as f:
        f.write(ico)
    print(f'Generated {ico_out} ({len(ico)} bytes)')

    out_dir = os.path.dirname(ico_out) or '.'
    for sz in [48, 192, 512]:
        px = create_icon(sz)
        png = write_png(px, sz, '')
        p = os.path.join(out_dir, f'icon_{sz}.png')
        with open(p, 'wb') as f:
            f.write(png)
        print(f'Generated {p} ({len(png)} bytes)')
