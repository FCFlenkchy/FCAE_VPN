#!/usr/bin/env python3
"""Generate FCAE VPN icon: blue circle with white 'FCAE' text centered."""
import struct, zlib, sys, os

FONT = {
    'F': [[1,1,1,1,0],[1,0,0,0,0],[1,0,0,0,0],[1,1,1,0,0],[1,0,0,0,0],[1,0,0,0,0],[1,0,0,0,0]],
    'C': [[0,1,1,1,0],[1,0,0,0,1],[1,0,0,0,0],[1,0,0,0,0],[1,0,0,0,0],[1,0,0,0,1],[0,1,1,1,0]],
    'A': [[0,1,1,1,0],[1,0,0,0,1],[1,0,0,0,1],[1,1,1,1,1],[1,0,0,0,1],[1,0,0,0,1],[1,0,0,0,1]],
    'E': [[1,1,1,1,1],[1,0,0,0,0],[1,0,0,0,0],[1,1,1,0,0],[1,0,0,0,0],[1,0,0,0,0],[1,1,1,1,1]],
}

def create_icon(size):
    bg = (0x1A, 0x3A, 0x5C)
    fg = (0xFF, 0xFF, 0xFF)
    border = (0x22, 0x44, 0x66)
    edge = (0x10, 0x28, 0x40)
    pixels = []
    # 4 chars * 5px + 3 gaps = 23px source, 7px tall
    src_w, src_h = 23, 7
    scale = max(1, (size - 6) // max(src_w, src_h))
    tw, th = src_w * scale, src_h * scale
    ox = (size - tw) // 2
    oy = (size - th) // 2

    for y in range(size):
        for x in range(size):
            dx, dy = x - size // 2, y - size // 2
            dist = (dx * dx + dy * dy) ** 0.5
            if dist > size * 0.48:
                pixels.append(edge); continue
            if dist > size * 0.44:
                pixels.append(border); continue

            tx, ty = x - ox, y - oy
            if 0 <= tx < tw and 0 <= ty < th:
                src_x = tx // scale
                src_y = ty // scale
                char_idx = src_x // 6  # 5px char + 1px gap
                px_in = src_x % 6
                if px_in < 5 and 0 <= src_y < 7 and char_idx < 4:
                    ch = 'FCAE'[char_idx]
                    if FONT[ch][src_y][px_in]:
                        pixels.append(fg); continue
            pixels.append(bg)
    return pixels

def make_ico():
    sizes = [16, 32, 48]
    icons = []
    for sz in sizes:
        px = create_icon(sz)
        mask = bytes(sz * ((sz + 7) // 8))
        hdr = struct.pack('<IiiHHIIiiII', 40, sz, sz * 2, 1, 32, 0, 0, 0, 0, 0, 0)
        data = b''
        for y in range(sz - 1, -1, -1):
            for x in range(sz):
                r, g, b = px[y * sz + x]
                data += bytes([b, g, r, 0xFF])
        icons.append((sz, hdr + data + mask))
    ico = struct.pack('<HHH', 0, 1, len(icons))
    off = 6 + len(icons) * 16
    for sz, d in icons:
        ico += struct.pack('<BBBBHHII', sz, sz, 0, 0, 1, 32, len(d), off)
        off += len(d)
    for _, d in icons:
        ico += d
    return ico

def write_png(pixels, size):
    raw = b''
    for y in range(size):
        raw += b'\x00'
        for x in range(size):
            r, g, b = pixels[y * size + x]
            raw += bytes([r, g, b, 0xFF])
    def chunk(ct, d):
        c = ct + d
        return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xFFFFFFFF)
    ihdr = struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', ihdr) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'')

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'icon.ico'
    d = os.path.dirname(out) or '.'
    ico = make_ico()
    with open(out, 'wb') as f:
        f.write(ico)
    print(f'{out} ({len(ico)} bytes)')
    for sz in [48, 192, 512]:
        p = os.path.join(d, f'icon_{sz}.png')
        with open(p, 'wb') as f:
            f.write(write_png(create_icon(sz), sz))
        print(f'{p}')
