#!/usr/bin/env python3
"""
Universal TXD Merger with PNG export and merge policies.

- Parses RenderWare TXD chunks from many platforms (PC/PS2/Xbox/GC).
- Merges many .txd files into one output.
- Deduplicates and resolves collisions with selectable merge policy.
- Exports textures from merged TXD as PNG (Pillow) or PPM (fallback).
- Supports DXT1/DXT3/DXT5 decoding (pure Python).
"""

from __future__ import annotations
import struct
import hashlib
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import math
import os

# Try to import Pillow for PNG output
try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

# -------------------- Constants --------------------
CHUNK_STRUCT        = 0x01
CHUNK_STRING        = 0x02
CHUNK_EXTENSION     = 0x03
CHUNK_PS2_EXTRA1    = 0x04
CHUNK_PS2_EXTRA2    = 0x08
CHUNK_PS2_EXTRA3    = 0x0C
CHUNK_SKY_MIPMAP    = 0x10
CHUNK_TEXTURE       = 0x15
CHUNK_TXD           = 0x16

# Representative target versions
TARGET_VERSION_BY_GAME = {
    'III':     0x00000310,
    'III_PC':  0x0003FFFF,
    'VC':      0x1003FFFF,
    'VC_PS2':  0x0C02FFFF,
    'SA':      0x1803FFFF,
    'UNKNOWN': 0x0800FFFF,
}

# DXT FourCC ints for comparisons
def fourcc(s: str) -> int:
    return struct.unpack('<I', s.encode('ascii'))[0]

FOURCC_DXT1 = fourcc('DXT1')
FOURCC_DXT2 = fourcc('DXT2')
FOURCC_DXT3 = fourcc('DXT3')
FOURCC_DXT4 = fourcc('DXT4')
FOURCC_DXT5 = fourcc('DXT5')

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# -------------------- Utilities --------------------
def read_u32(data: bytes, offset: int, endian: str = '<') -> int:
    return struct.unpack_from(endian + 'I', data, offset)[0]

def read_u16(data: bytes, offset: int, endian: str = '<') -> int:
    return struct.unpack_from(endian + 'H', data, offset)[0]

def pack_u32(v: int, endian: str = '<') -> bytes:
    return struct.pack(endian + 'I', v)

# -------------------- DXT Decoders (pure Python) --------------------
# DXT1/3/5 decoding adapted for straightforward use. Returns bytes RGBA (width*height*4).

def _unpack_rgb565(v):
    r = ((v >> 11) & 0x1F) * 255 // 31
    g = ((v >> 5) & 0x3F) * 255 // 63
    b = (v & 0x1F) * 255 // 31
    return r, g, b

def decode_dxt1(data: bytes, width: int, height: int) -> bytes:
    out = bytearray(width * height * 4)
    pos = 0
    for y in range(0, height, 4):
        for x in range(0, width, 4):
            c0, c1 = struct.unpack_from('<HH', data, pos)
            pos += 4
            bits = struct.unpack_from('<I', data, pos)[0]
            pos += 4
            r0, g0, b0 = _unpack_rgb565(c0)
            r1, g1, b1 = _unpack_rgb565(c1)
            colors = [(r0, g0, b0, 255), (r1, g1, b1, 255)]
            if c0 > c1:
                colors.append(((2*r0 + r1)//3, (2*g0 + g1)//3, (2*b0 + b1)//3, 255))
                colors.append(((r0 + 2*r1)//3, (g0 + 2*g1)//3, (b0 + 2*b1)//3, 255))
            else:
                colors.append(((r0 + r1)//2, (g0 + g1)//2, (b0 + b1)//2, 255))
                colors.append((0,0,0,0))
            for j in range(4):
                for i in range(4):
                    idx = bits & 0x3
                    bits >>= 2
                    px = x + i
                    py = y + j
                    if px < width and py < height:
                        off = (py*width + px)*4
                        cr, cg, cb, ca = colors[idx]
                        out[off:off+4] = bytes((cr, cg, cb, ca))
    return bytes(out)

def decode_dxt3(data: bytes, width: int, height: int) -> bytes:
    out = bytearray(width * height * 4)
    pos = 0
    for y in range(0, height, 4):
        for x in range(0, width, 4):
            # alpha: 8 bytes, 4x4 4-bit values
            alpha_bits = struct.unpack_from('<Q', data, pos)[0]
            pos += 8
            # color block as DXT1
            c0, c1 = struct.unpack_from('<HH', data, pos); pos += 4
            bits = struct.unpack_from('<I', data, pos)[0]; pos += 4
            r0, g0, b0 = _unpack_rgb565(c0)
            r1, g1, b1 = _unpack_rgb565(c1)
            colors = [(r0, g0, b0), (r1, g1, b1)]
            if c0 > c1:
                colors.append(((2*r0 + r1)//3, (2*g0 + g1)//3, (2*b0 + b1)//3))
                colors.append(((r0 + 2*r1)//3, (g0 + 2*g1)//3, (b0 + 2*b1)//3))
            else:
                colors.append(((r0 + r1)//2, (g0 + g1)//2, (b0 + b1)//2))
                colors.append((0,0,0))
            for j in range(4):
                for i in range(4):
                    a = alpha_bits & 0xF
                    alpha_bits >>= 4
                    idx = bits & 0x3
                    bits >>= 2
                    px = x + i
                    py = y + j
                    if px < width and py < height:
                        off = (py*width + px)*4
                        cr, cg, cb = colors[idx]
                        ca = (a * 17)  # 4-bit to 8-bit
                        out[off:off+4] = bytes((cr, cg, cb, ca))
    return bytes(out)

def _interp(a, b, f, denom):
    return ( ( (denom - f) * a + f * b ) // denom )

def decode_dxt5(data: bytes, width: int, height: int) -> bytes:
    out = bytearray(width * height * 4)
    pos = 0
    for y in range(0, height, 4):
        for x in range(0, width, 4):
            a0 = data[pos]; a1 = data[pos+1]; pos += 2
            alpha_bits = 0
            # read 6 bytes of alpha indices into 48-bit value (little-endian)
            alpha_bits = int.from_bytes(data[pos:pos+6], 'little')
            pos += 6
            c0, c1 = struct.unpack_from('<HH', data, pos); pos += 4
            bits = struct.unpack_from('<I', data, pos)[0]; pos += 4
            r0, g0, b0 = _unpack_rgb565(c0)
            r1, g1, b1 = _unpack_rgb565(c1)
            colors = [(r0, g0, b0), (r1, g1, b1)]
            if c0 > c1:
                colors.append(((2*r0 + r1)//3, (2*g0 + g1)//3, (2*b0 + 2*g1)//3 if False else (2*g0 + g1)//3, (2*b0 + b1)//3))  # placeholder
                colors[2] = ((2*r0 + r1)//3, (2*g0 + g1)//3, (2*b0 + b1)//3)
                colors.append(((r0 + 2*r1)//3, (g0 + 2*g1)//3, (b0 + 2*b1)//3))
            else:
                colors.append(((r0 + r1)//2, (g0 + g1)//2, (b0 + b1)//2))
                colors.append((0,0,0))
            # For alpha palette:
            alpha_vals = [a0, a1]
            if a0 > a1:
                for i in range(1,6):
                    alpha_vals.append( ( ( (6 - i) * a0 + i * a1 ) // 6 ) )
            else:
                for i in range(1,4):
                    alpha_vals.append( ( ( (4 - i) * a0 + i * a1 ) // 4 ) )
                alpha_vals += [0, 255]
            # now write pixels
            for j in range(4):
                for i in range(4):
                    idx = alpha_bits & 0x7
                    alpha_bits >>= 3
                    color_idx = bits & 0x3
                    bits >>= 2
                    px = x + i
                    py = y + j
                    if px < width and py < height:
                        off = (py*width + px)*4
                        cr, cg, cb = colors[color_idx]
                        ca = alpha_vals[idx]
                        out[off:off+4] = bytes((cr, cg, cb, ca))
    return bytes(out)

# A small wrapper to pick decoder
def decode_texture_data(d3d_format: int, width: int, height: int, data: bytes) -> tuple[bytes,int,int]:
    """
    Returns (rgba_bytes, width, height). Supports:
     - FourCC DXT1/DXT3/DXT5
     - D3D codes (if used) for uncompressed (we expect RGBA32/RGB32)
     - For uncompressed, we assume data is in 32-bit RGBA or 24-bit RGB row-major.
    """
    # FourCC check: if value is printable FourCC (>= 0x20202020)
    if d3d_format in (FOURCC_DXT1, ) or d3d_format == 0x44585431:  # 'DXT1'
        rgba = decode_dxt1(data, width, height)
        return rgba, width, height
    if d3d_format in (FOURCC_DXT3, ) or d3d_format == 0x44585433:  # 'DXT3'
        rgba = decode_dxt3(data, width, height)
        return rgba, width, height
    if d3d_format in (FOURCC_DXT5, ) or d3d_format == 0x44585435:  # 'DXT5'
        rgba = decode_dxt5(data, width, height)
        return rgba, width, height

    # Known D3D numeric formats (as small integers)
    # 21 => RGBA32 (4 bytes/pixel)
    # 22 => RGB32 (3 bytes/pixel)
    if d3d_format == 21:  # RGBA32
        expected = width * height * 4
        if len(data) >= expected:
            return data[:expected], width, height
        else:
            raise ValueError("Not enough data for RGBA32")
    if d3d_format == 22:  # RGB32 (24-bit)
        expected = width * height * 3
        if len(data) >= expected:
            # expand to RGBA
            out = bytearray(width * height * 4)
            si = 0
            for pi in range(width*height):
                r = data[si]; g = data[si+1]; b = data[si+2]; si += 3
                off = pi*4
                out[off:off+4] = bytes((r,g,b,255))
            return bytes(out), width, height
    # fallback: unknown format, return raw bytes and let caller skip
    raise ValueError(f"Unsupported or unknown texture format: {d3d_format}")

# -------------------- TXD Parser / Merger --------------------
class Texture:
    __slots__ = ('name', 'raw_chunk', 'payload', 'hash', 'source')
    def __init__(self, name: str, raw_chunk: bytes, payload: bytes, source: Path | None = None):
        self.name = name or ''
        self.raw_chunk = raw_chunk
        self.payload = payload
        self.hash = hashlib.md5(raw_chunk).hexdigest()
        self.source = source

    def update_name_in_payload(self, new_name: str, endian: str = '<') -> bool:
        """
        Update first CHUNK_STRUCT payload's texture_name at offset 8..8+32
        Returns True if updated.
        """
        try:
            for cid, ver, inner_payload, pos, total in TxdFile.parse_chunks(self.payload, 0, None, endian):
                if cid == CHUNK_STRUCT and len(inner_payload) >= 8 + 32:
                    # inner_payload is the payload bytes of that struct
                    name_bytes = new_name.encode('ascii', errors='ignore')[:32].ljust(32, b'\x00')
                    # rebuild payload: prefix, inner_chunk header (12 bytes) already excluded because parse_chunks yields inner_payload only
                    # Need to rebuild the self.payload with replacement of inner_payload
                    # Find position where this inner chunk payload sits within self.payload:
                    inner_header_start = pos
                    inner_payload_start = inner_header_start + 12
                    before = self.payload[:inner_payload_start]
                    after = self.payload[inner_payload_start + len(inner_payload):]
                    new_inner_payload = inner_payload[:8] + name_bytes + inner_payload[8 + 32:]
                    self.payload = before + new_inner_payload + after
                    self.raw_chunk = self.raw_chunk[:12] + self.payload
                    self.name = new_name
                    self.hash = hashlib.md5(self.raw_chunk).hexdigest()
                    return True
        except Exception:
            logging.exception("Error updating name in payload")
        return False

class TxdFile:
    def __init__(self):
        self.textures: list[Texture] = []
        self.version: int = 0
        self.game: str = ''
        self.raw_data: bytes = b''
        self.endian: str = '<'

    @staticmethod
    def parse_chunks(data: bytes, offset: int = 0, length: int | None = None, endian: str = '<'):
        if length is None:
            end = len(data)
        else:
            end = offset + length
        pos = offset
        header_size = 12
        fmt = endian + 'III'
        MAX_CHUNK_SIZE = 1 << 30
        while pos + header_size <= end:
            try:
                cid, size, ver = struct.unpack_from(fmt, data, pos)
            except struct.error:
                break
            total = header_size + size
            if size > MAX_CHUNK_SIZE or total < header_size:
                logging.warning("Absurd chunk size at %d: %d", pos, size)
                break
            if pos + total > end:
                logging.warning("Chunk overflow at %d: %d > %d", pos, total, end)
                break
            payload = data[pos + header_size: pos + total]
            yield cid, ver, payload, pos, total
            pos += total

    @staticmethod
    def detect_game_from_version(v: int) -> str:
        top = v & 0xFF000000
        if top == 0x18000000:
            return 'SA'
        if top == 0x10000000:
            return 'VC'
        if top == 0x00000000:
            return 'III'
        for g, val in TARGET_VERSION_BY_GAME.items():
            if v == val:
                return g
        return 'UNKNOWN'

    @staticmethod
    def find_texture_chunks(data: bytes, endian: str = '<'):
        stack = [data]
        while stack:
            blk = stack.pop()
            for cid, ver, payload, pos, total in TxdFile.parse_chunks(blk, 0, None, endian):
                if cid == CHUNK_TEXTURE:
                    yield ver, payload, blk, pos, total
                else:
                    if payload:
                        stack.append(payload)

    @staticmethod
    def extract_name(payload: bytes, endian: str = '<') -> str | None:
        """
        Find first CHUNK_STRUCT inside payload and extract name at offset [8:40] of its payload.
        Fallback: printable ascii run.
        """
        try:
            for cid, ver, p, pos, total in TxdFile.parse_chunks(payload, 0, None, endian):
                if cid == CHUNK_STRUCT and len(p) >= 8 + 32:
                    raw = p[8:8+32].split(b'\x00',1)[0]
                    return raw.decode('ascii', 'ignore')
            # fallback
            probe = payload[:256].split(b'\x00',1)[0]
            filtered = bytes([c for c in probe if 32 <= c < 127])
            if filtered:
                return filtered.decode('ascii','ignore')[:32]
        except Exception:
            pass
        return None

    def _detect_endianness(self, raw: bytes) -> str:
        if len(raw) < 12:
            return '<'
        try:
            le = struct.unpack_from('<I', raw, 0)[0]
            if le == CHUNK_TXD:
                return '<'
            be = struct.unpack_from('>I', raw, 0)[0]
            if be == CHUNK_TXD:
                return '>'
        except Exception:
            pass
        return '<'

    def load(self, path: Path) -> 'TxdFile':
        self.raw_data = path.read_bytes()
        self.endian = self._detect_endianness(self.raw_data)
        try:
            cid, size, version = struct.unpack_from(self.endian + 'III', self.raw_data, 0)
        except struct.error as e:
            raise ValueError(f"{path.name}: invalid header ({e})")
        if cid != CHUNK_TXD:
            raise ValueError(f"{path.name}: not a TXD (cid={cid})")
        if 12 + size > len(self.raw_data):
            raise ValueError(f"{path.name}: declared size exceeds file")
        self.version = version
        self.game = TxdFile.detect_game_from_version(version)
        payload = self.raw_data[12:12+size]
        seen = set()
        textures = []
        for ver, tex_payload, blk, pos, total in TxdFile.find_texture_chunks(payload, self.endian):
            raw_chunk = blk[pos:pos+total]
            h = hashlib.md5(raw_chunk).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            name = TxdFile.extract_name(tex_payload, self.endian) or ''
            textures.append(Texture(name, raw_chunk, tex_payload, source=path))
        self.textures = textures
        logging.info("Loaded %d textures from %s", len(textures), path.name)
        return self

    def save(self, path: Path, target_version: int, out_endian: str = '<', policy: str = 'keep_first') -> None:
        """
        Save merged textures to a TXD file. Policy currently applies to duplicate handling prior to saving.
        """
        # Build map depending on policy
        if policy == 'keep_last':
            # iterate in order, keep last => overwrite map with later entries
            name_map = {}
            hash_map = {}
            for tex in self.textures:
                name_map[tex.name] = tex
                hash_map[tex.hash] = tex
            textures = list(name_map.values())
        elif policy == 'skip_duplicates':
            hash_map = {}
            textures = []
            for tex in self.textures:
                if tex.hash in hash_map:
                    continue
                hash_map[tex.hash] = tex
                textures.append(tex)
        elif policy == 'auto_rename':
            # dedupe by hash but ensure names unique by renaming different contents
            hash_map = {}
            name_counts = {}
            textures = []
            for tex in self.textures:
                if tex.hash in hash_map:
                    continue
                hash_map[tex.hash] = tex
                base = (tex.name or 'texture').strip() or 'texture'
                if base in name_counts:
                    name_counts[base] += 1
                    new_name = f"{base}_{name_counts[base]:02d}"
                    tex.update_name_in_payload(new_name, out_endian)
                else:
                    name_counts[base] = 0
                    tex.name = base
                textures.append(tex)
        else:  # keep_first (default)
            seen_hash = set()
            name_taken = set()
            out_list = []
            for tex in self.textures:
                if tex.hash in seen_hash:
                    continue
                # if name collision (same name but different content), we keep first by default
                if tex.name in name_taken:
                    # rename new one to avoid collision in the final list (append index) but don't change behavior
                    idx = 1
                    base = (tex.name or 'texture').strip() or 'texture'
                    while f"{base}_{idx:02d}" in name_taken:
                        idx += 1
                    new_name = f"{base}_{idx:02d}"
                    tex.update_name_in_payload(new_name, out_endian)
                name_taken.add(tex.name)
                seen_hash.add(tex.hash)
                out_list.append(tex)
            textures = out_list

        # Now build txd bytes
        # txd_info_t as CHUNK_STRUCT payload: uint16 count, uint16 unknown
        count = len(textures)
        struct_payload = struct.pack(out_endian + 'HH', count, 0)
        struct_chunk = struct.pack(out_endian + 'III', CHUNK_STRUCT, len(struct_payload), target_version) + struct_payload
        body = bytearray(struct_chunk)
        for tex in textures:
            body += struct.pack(out_endian + 'III', CHUNK_TEXTURE, len(tex.payload), target_version)
            body += tex.payload
        # zero-length extension
        body += struct.pack(out_endian + 'III', CHUNK_EXTENSION, 0, target_version)
        header = struct.pack(out_endian + 'III', CHUNK_TXD, len(body), target_version)
        path.write_bytes(header + body)
        logging.info("Saved merged TXD with %d textures to %s", count, str(path))

    # --- helpers to parse texture-data struct for decoding ---
    @staticmethod
    def parse_texture_data_payload(payload: bytes, endian: str = '<'):
        """
        Find inner CHUNK_STRUCT which is txd_texture_data and parse fields.
        Returns dict with keys:
         - version, filter_flags, texture_name, alpha_name, alpha_flags,
           d3d_format, width, height, depth, mipmap_count, texcode_type, flags,
           palette (bytes or None), data (bytes first mipmap), mipmaps (list of bytes for additional)
        """
        for cid, ver, p, pos, total in TxdFile.parse_chunks(payload, 0, None, endian):
            if cid == CHUNK_STRUCT and len(p) >= 88:  # conservative size check
                # parse fields according to txd_texture_data_t layout
                off = 0
                version = struct.unpack_from(endian + 'I', p, off)[0]; off += 4
                filter_flags = struct.unpack_from(endian + 'I', p, off)[0]; off += 4
                texname = p[off:off+32].split(b'\x00',1)[0].decode('ascii','ignore'); off += 32
                alphaname = p[off:off+32].split(b'\x00',1)[0].decode('ascii','ignore'); off += 32
                alpha_flags = struct.unpack_from(endian + 'I', p, off)[0]; off += 4
                d3d_format = struct.unpack_from(endian + 'I', p, off)[0]; off += 4
                width = struct.unpack_from(endian + 'H', p, off)[0]; off += 2
                height = struct.unpack_from(endian + 'H', p, off)[0]; off += 2
                depth = p[off]; off += 1
                mipmap_count = p[off]; off += 1
                texcode_type = p[off]; off += 1
                flags = p[off]; off += 1
                palette = None
                if depth == 8:
                    pal_size = 256 * 4
                    palette = p[off:off+pal_size]
                    off += pal_size
                # data_size
                if off + 4 > len(p):
                    raise ValueError("Unexpected end reading data_size")
                data_size = struct.unpack_from(endian + 'I', p, off)[0]; off += 4
                data = p[off:off+data_size]; off += data_size
                mipmaps = []
                for mi in range(max(0, mipmap_count - 1)):
                    if off + 4 > len(p): break
                    msz = struct.unpack_from(endian + 'I', p, off)[0]; off += 4
                    mip = p[off:off+msz]; off += msz
                    mipmaps.append(mip)
                return {
                    'version': version, 'filter_flags': filter_flags,
                    'texture_name': texname, 'alpha_name': alphaname,
                    'alpha_flags': alpha_flags, 'd3d_format': d3d_format,
                    'width': width, 'height': height, 'depth': depth,
                    'mipmap_count': mipmap_count, 'texcode_type': texcode_type,
                    'flags': flags, 'palette': palette, 'data': data, 'mipmaps': mipmaps
                }
        return None

# -------------------- UI --------------------
class UniversalMergerApp:
    def __init__(self, master):
        master.title("Universal TXD Merger — Export & Policies")
        self.input_dir = tk.StringVar()
        self.output_file = tk.StringVar()
        self.version_choice = tk.StringVar(value='Detect')
        self.endian_choice = tk.StringVar(value='LE')
        self.policy_choice = tk.StringVar(value='keep_first')

        frame = ttk.Frame(master, padding=10)
        frame.grid(sticky='nsew')

        ttk.Label(frame, text="1) Select folder with TXD files").grid(row=0, column=0, sticky='w')
        ttk.Button(frame, text="Select Folder", command=self.select_folder, width=20).grid(row=0, column=1, sticky='e')

        ttk.Label(frame, text="2) Choose output base file").grid(row=1, column=0, sticky='w')
        ttk.Button(frame, text="Save As", command=self.select_output, width=20).grid(row=1, column=1, sticky='e')

        ttk.Label(frame, text="3) Version mode").grid(row=2, column=0, sticky='w')
        values = ['Detect'] + list(TARGET_VERSION_BY_GAME.keys())
        ttk.Combobox(frame, textvariable=self.version_choice, values=values, state='readonly', width=18).grid(row=2, column=1, sticky='e')

        ttk.Label(frame, text="4) Output endianness").grid(row=3, column=0, sticky='w')
        ttk.Combobox(frame, textvariable=self.endian_choice, values=['LE','BE'], state='readonly', width=18).grid(row=3, column=1, sticky='e')

        ttk.Label(frame, text="5) Merge policy").grid(row=4, column=0, sticky='w')
        ttk.Combobox(frame, textvariable=self.policy_choice,
                     values=['keep_first','keep_last','skip_duplicates','auto_rename'],
                     state='readonly', width=18).grid(row=4, column=1, sticky='e')

        self.progress = ttk.Progressbar(frame, orient='horizontal', length=520, mode='determinate')
        self.progress.grid(row=5, column=0, columnspan=2, pady=8)

        ttk.Button(frame, text="Merge", command=self.merge, width=20).grid(row=6, column=0, pady=6)
        ttk.Button(frame, text="Export Textures (Merged)", command=self.export_merged_textures, width=24).grid(row=6, column=1, pady=6)
        ttk.Button(frame, text="Quit", command=master.quit, width=20).grid(row=7, column=1, pady=6)

        self.log = tk.Text(frame, height=14, width=78, state='disabled')
        self.log.grid(row=8, column=0, columnspan=2, pady=(6,0))

        frame.columnconfigure(0, weight=1)

        # runtime storage
        self.loaded_txds: list[tuple[Path, TxdFile]] = []
        self.last_merged: TxdFile | None = None
        self.last_merged_path: Path | None = None

    def _log(self, s: str):
        self.log['state'] = 'normal'
        self.log.insert('end', s + '\n')
        self.log.see('end')
        self.log['state'] = 'disabled'
        logging.info(s)

    def select_folder(self):
        d = filedialog.askdirectory()
        if d:
            self.input_dir.set(d)
            self._log(f"Selected: {d}")

    def select_output(self):
        f = filedialog.asksaveasfilename(defaultextension='.txd', filetypes=[('TXD Files','*.txd')])
        if f:
            self.output_file.set(f)
            self._log(f"Output base: {f}")

    def merge(self):
        in_dir = Path(self.input_dir.get())
        out_base = Path(self.output_file.get()) if self.output_file.get() else None
        if not in_dir.exists() or not in_dir.is_dir():
            messagebox.showerror("Error", "Select valid input folder.")
            return
        txd_paths = sorted(in_dir.glob('*.txd'), key=lambda p: p.name.lower())
        if not txd_paths:
            messagebox.showerror("Error", "No .txd files found.")
            return
        if not out_base:
            messagebox.showerror("Error", "Choose output Save As file.")
            return
        self.progress['maximum'] = len(txd_paths)
        self.progress['value'] = 0
        self.loaded_txds = []
        failures = []
        self._log(f"Loading {len(txd_paths)} TXDs...")
        with ThreadPoolExecutor() as exe:
            futures = {exe.submit(TxdFile().load, p): p for p in txd_paths}
            for fut in as_completed(futures):
                p = futures[fut]
                try:
                    txd = fut.result()
                    self.loaded_txds.append((p, txd))
                    self._log(f"Loaded {p.name} -> {len(txd.textures)} textures")
                except Exception as e:
                    failures.append((p, str(e)))
                    self._log(f"Failed {p.name}: {e}")
                finally:
                    self.progress.step()
        if not self.loaded_txds:
            messagebox.showerror("Error","No valid TXDs loaded.")
            return
        # grouping
        mode = self.version_choice.get()
        groups = {}
        if mode == 'Detect':
            for _, txd in self.loaded_txds:
                key = (txd.game, txd.version)
                groups.setdefault(key, []).append(txd)
            self._log(f"Grouping into {len(groups)} groups by detected version.")
        else:
            target_ver = TARGET_VERSION_BY_GAME.get(mode, TARGET_VERSION_BY_GAME['SA'])
            groups = {('FORCED', target_ver): [txd for _, txd in self.loaded_txds]}
            self._log(f"Forcing target ver {mode} => {target_ver:#x}")
        out_endian = '<' if self.endian_choice.get() == 'LE' else '>'
        policy = self.policy_choice.get()
        out_paths = []
        for (game, ver), group in groups.items():
            merged = TxdFile()
            merged.version = ver
            merged.game = game
            # flatten textures preserving source order (earlier files first)
            merged.textures = [tex for txd in group for tex in txd.textures]
            if mode == 'Detect':
                out_name = f"{out_base.stem}_{game}_ver{ver:#x}{out_base.suffix}"
            else:
                out_name = f"{out_base.stem}_merged_ver{ver:#x}{out_base.suffix}"
            out_path = out_base.with_name(out_name)
            try:
                merged.save(out_path, ver, out_endian, policy=policy)
                out_paths.append(out_path)
                self._log(f"Saved {out_path.name} ({len(merged.textures)} textures)")
                self.last_merged = merged
                self.last_merged_path = out_path
            except Exception as e:
                self._log(f"Failed to save {out_path.name}: {e}")
        if failures:
            self._log(f"{len(failures)} failed to load.")
        else:
            self._log("All loaded successfully.")
        messagebox.showinfo("Done", f"Merged {len(out_paths)} output(s).")

    def export_merged_textures(self):
        if self.last_merged is None:
            messagebox.showerror("Error","No merged TXD available. Run Merge first.")
            return
        out_dir = filedialog.askdirectory(title="Select folder to export textures")
        if not out_dir:
            return
        out_dir = Path(out_dir)
        merged = self.last_merged
        self._log(f"Exporting {len(merged.textures)} textures to {out_dir} ...")
        failures = 0
        exported = 0
        for i, tex in enumerate(merged.textures):
            # parse texture-data payload
            try:
                parsed = TxdFile.parse_texture_data_payload(tex.payload, endian=self.last_merged.endian)
                if not parsed:
                    self._log(f"[{i}] No texture-data found for {tex.name}; skipping")
                    failures += 1
                    continue
                d3d = parsed['d3d_format']
                w = parsed['width']; h = parsed['height']
                raw = parsed['data']
                # attempt decode
                try:
                    rgba, rw, rh = decode_texture_data(d3d, w, h, raw)
                except Exception as e:
                    self._log(f"[{i}] Failed to decode {tex.name}: {e}")
                    failures += 1
                    continue
                # save to file (PNG if Pillow available else PPM)
                safe_name = (tex.name or f"tex_{i:04d}").replace('..','_').replace('/','_').strip()
                if PIL_AVAILABLE:
                    img = Image.frombytes('RGBA', (rw, rh), rgba)
                    out_path = out_dir / f"{safe_name}.png"
                    img.save(out_path)
                else:
                    # PPM (binary P6 for RGB, but we have RGBA — strip alpha)
                    out_path = out_dir / f"{safe_name}.ppm"
                    with open(out_path, 'wb') as fh:
                        fh.write(f"P6\n{rw} {rh}\n255\n".encode('ascii'))
                        # write RGB only
                        for p in range(rw*rh):
                            off = p*4
                            fh.write(bytes((rgba[off], rgba[off+1], rgba[off+2])))
                exported += 1
                if i % 50 == 0:
                    self._log(f"Exported {i+1}/{len(merged.textures)} ...")
            except Exception as e:
                self._log(f"[{i}] Error exporting {tex.name}: {e}")
                failures += 1
        self._log(f"Export complete: {exported} exported, {failures} failed. Output folder: {out_dir}")
        messagebox.showinfo("Export complete", f"{exported} textures exported, {failures} failed.\nFolder: {out_dir}")

# -------------------- Run --------------------
if __name__ == '__main__':
    root = tk.Tk()
    UniversalMergerApp(root)
    root.mainloop()
