#!/usr/bin/env python3
"""
TXD Merger — Simple UI
- Minimal UI: Select Folder, Save As, Version selector (Detect / III / VC / SA), Merge.
- Preserves robust parsing: endian detection, version detection, duplicate-content dedupe,
  name-collision handling (in-memory labels), parallel loading for speed.
"""

import struct
import hashlib
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# --- TXD Chunk Constants (expanded, named, tagged) -------------------------

# Core / main TXD chunks (RenderWare standard-ish)
CHUNK_TEX_DICT      = 0x00   # Texture dictionary placeholder (PC/Xbox)
CHUNK_STRUCT        = 0x01   # Structural chunk (contains image metadata)
CHUNK_STRING        = 0x02   # String block (PS2 TXDs)
CHUNK_EXTENSION     = 0x03   # Extension / extra data (often child of Texture Native or TXD)
CHUNK_PS2_EXTRA1    = 0x04   # PS2-specific extra struct inside Texture Native
# (0x05 - 0x0F) reserved / vendor-specific in many RW builds
CHUNK_PS2_EXTRA2    = 0x08   # PS2-specific string block (GTA III / SA)
CHUNK_PS2_EXTRA3    = 0x0C   # PS2-specific string block (GTA VC / PS2 games)
CHUNK_SKY_MIPMAP    = 0x10   # Sky Mipmap Values (PS2 TXDs — stored inside Extension)
CHUNK_TEXTURE       = 0x15   # Texture Native chunk (main image + mipmaps)
CHUNK_TXD           = 0x16   # Texture Dictionary (top-level container for a TXD)

# Structural / size constants (PS2 TXD internal structs)
CHUNK_STRUCT_SMALL  = 0x40    # small struct block seen inside PS2 Texture Native
CHUNK_STRUCT_LARGE  = 0x8A0   # large struct used inside GTA SA (PS2)
CHUNK_STRUCT_XL     = 0x8E0   # extra-large struct used in GTA III (PS2)
CHUNK_STRUCT_VC     = 0x5830  # huge struct used in GTA VC / similar PS2 files

# Representative target version to write when forcing a platform
TARGET_VERSION_BY_GAME = {
    'III': 0x00000310,
    'VC':  0x1003FFFF,
    'SA':  0x1803FFFF,
}

# Raster pixel formats (common across RenderWare platforms)
RASTER_DEFAULT      = 0x00
RASTER_1555         = 0x01
RASTER_565          = 0x02
RASTER_4444         = 0x03
RASTER_LUM          = 0x04
RASTER_8888         = 0x05
RASTER_888          = 0x06
RASTER_16           = 0x07
RASTER_24           = 0x08
RASTER_32           = 0x09
RASTER_555          = 0x0A

# Direct3D pixel formats (PC / Xbox)
D3D_8888            = 21
D3D_888             = 22
D3D_565             = 23
D3D_555             = 24
D3D_1555            = 25
D3D_4444            = 26

D3DFMT_L8           = 50
D3DFMT_A8L8         = 51

D3D_DXT1            = 827611204
D3D_DXT2            = 844388420
D3D_DXT3            = 861165636
D3D_DXT4            = 877942852
D3D_DXT5            = 894720068

# D3D Compression type identifiers
D3D_COMPRESS_DXT1   = 1
D3D_COMPRESS_DXT2   = 2
D3D_COMPRESS_DXT3   = 3
D3D_COMPRESS_DXT4   = 4
D3D_COMPRESS_DXT5   = 5

# Palette types
PALETTE_NONE        = 0
PALETTE_8           = 1
PALETTE_4           = 2
PALETTE_4_LSB       = 3

# Device / platform types
DEVICE_NONE         = 0
DEVICE_D3D8         = 1
DEVICE_D3D9         = 2
DEVICE_GC           = 3   # GameCube (probable mapping)
DEVICE_PS2          = 6
DEVICE_XBOX         = 8
DEVICE_PSP          = 9

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# --- Utility reading helpers ------------------------------------------------
def read_u32(data: bytes, offset: int, endian: str = '<') -> int:
    return struct.unpack_from(endian + 'I', data, offset)[0]


# --- Texture container ------------------------------------------------------
class Texture:
    __slots__ = ('name', 'payload', 'hash')
    def __init__(self, name: str, raw_chunk: bytes, payload: bytes):
        self.name = name
        self.payload = payload
        self.hash = hashlib.md5(raw_chunk).hexdigest()


# --- TXD parsing / merging class --------------------------------------------
class TxdFile:
    def __init__(self):
        self.textures: list[Texture] = []
        self.version: int = 0
        self.game: str = ''
        self.raw_data: bytes = b''
        self.endian: str = '<'  # '<' little (PC), '>' big (Xbox-ish)

    @staticmethod
    def parse_chunks(data: bytes, offset: int = 0, length: int = None, endian: str = '<'):
        """
        Generator that yields (chunk_id, version, payload_bytes, chunk_offset_within_data, total_chunk_size).
        Each chunk header is (uint32 id, uint32 size, uint32 version).
        """
        if length is None:
            end = len(data)
        else:
            end = offset + length
        pos = offset
        header_fmt = endian + 'III'
        header_size = 12
        # sanity limit (avoid pathological sizes)
        MAX_CHUNK_SIZE = 1 << 30
        while pos + header_size <= end:
            try:
                cid, size, ver = struct.unpack_from(header_fmt, data, pos)
            except struct.error:
                break
            total = header_size + size
            # validation
            if size > MAX_CHUNK_SIZE or total < header_size:
                logging.warning('Chunk at %d claims absurd size (%d). Stopping parse.', pos, size)
                break
            if pos + total > end:
                logging.warning('Invalid/overflow chunk at pos %d (cid=%#x, size=%d), stopping.', pos, cid, size)
                break
            chunk = data[pos:pos + total]
            payload = chunk[header_size:]
            yield cid, ver, payload, pos, total
            pos += total

    @staticmethod
    def detect_game_from_version(v: int) -> str:
        """
        Use a simple heuristic: the top byte of the version value often identifies the target:
          - 0x18xxxxxx -> San Andreas
          - 0x10xxxxxx -> Vice City
          - 0x00xxxxxx -> GTA III / older
        Fall back to exact mapping if present.
        """
        top = v & 0xFF000000
        if top == 0x18000000:
            return 'SA'
        if top == 0x10000000:
            return 'VC'
        if top == 0x00000000:
            return 'III'
        # exact matches
        for g, val in TARGET_VERSION_BY_GAME.items():
            if v == val:
                return g
        # default fallback
        return 'SA'

    @staticmethod
    def find_texture_chunks(data: bytes, endian: str = '<'):
        """
        Walk chunk tree (breadth via stack) and yield any CHUNK_TEXTURE entries found.
        Yields (version, payload, containing_block_bytes, pos_within_block, total_chunk_size)
        """
        stack = [data]
        while stack:
            blk = stack.pop()
            for cid, ver, payload, pos, total in TxdFile.parse_chunks(blk, 0, None, endian):
                if cid == CHUNK_TEXTURE:
                    yield ver, payload, blk, pos, total
                else:
                    # push payload to explore nested chunks
                    if payload:
                        stack.append(payload)

    @staticmethod
    def extract_name(chunk_payload: bytes, endian: str = '<') -> str | None:
        """
        Try to extract a readable name from the texture chunk payload:
        1) look for a nested CHUNK_STRUCT and a likely name area inside it
        2) fallback: scan first 256 bytes for printable ascii, stop at NUL
        """
        for cid, ver, payload, _, _ in TxdFile.parse_chunks(chunk_payload, 0, None, endian):
            if cid == CHUNK_STRUCT and len(payload) >= 12:
                # Many TXD formats store a short name or label near the start of the struct.
                raw_name = payload[8:8 + 32]  # try a 32-byte window
                raw_name = raw_name.split(b"\x00", 1)[0]
                if raw_name:
                    try:
                        return raw_name.decode('ascii', 'ignore')
                    except Exception:
                        pass
        # fallback: first printable ASCII bytes in first 256 bytes
        try:
            probe = chunk_payload[:256]
            # split on first NUL and then ensure printable subset
            raw = probe.split(b'\x00', 1)[0]
            # filter to ASCII-printable characters
            filtered = bytes([c for c in raw if 32 <= c < 127])
            if filtered:
                return filtered.decode('ascii', 'ignore')[:32]
        except Exception:
            pass
        return None

    def _detect_endianness(self, raw: bytes) -> str:
        """
        If the first header uint32 equals CHUNK_TXD in little-endian, it's LE.
        If equals CHUNK_TXD in big-endian, it's BE.
        Fallback to LE.
        """
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
            raise ValueError(f"{path.name} is not a valid TXD (cid={cid})")

        # validate that top-level size fits in file
        if 12 + size > len(self.raw_data):
            raise ValueError(f"{path.name}: header size ({size}) exceeds file length ({len(self.raw_data)}).")

        self.version = version
        self.game = TxdFile.detect_game_from_version(version)

        payload = self.raw_data[12:12 + size]
        seen_hashes = set()
        textures: list[Texture] = []

        for ver, tex_payload, blk, pos, total in TxdFile.find_texture_chunks(payload, endian=self.endian):
            raw_chunk = blk[pos:pos + total]
            h = hashlib.md5(raw_chunk).hexdigest()
            if h in seen_hashes:
                continue
            seen_hashes.add(h)
            name = TxdFile.extract_name(tex_payload, endian=self.endian) or ''
            textures.append(Texture(name, raw_chunk, tex_payload))

        self.textures = textures
        logging.info('Loaded %d textures from %s (Game=%s, Ver=%#x, endian=%s)',
                     len(textures), path.name, self.game, version, 'LE' if self.endian == '<' else 'BE')
        return self

    def save(self, path: Path, target_version: int) -> None:
        """
        Save a merged TXD. For now we write little-endian PC-style files ('<').
        If you need other platform endian, change out_endian accordingly.
        """
        out_endian = '<'  # change to '>' if you want big-endian output (Xbox/PS2-specific flows may differ)

        # Deduplicate by content hash
        hash_map = {}
        for tex in self.textures:
            if tex.hash not in hash_map:
                hash_map[tex.hash] = tex

        textures = list(hash_map.values())

        # Resolve duplicate names (same name but different content) with suffixes
        name_counts = {}
        for tex in textures:
            base = (tex.name or 'texture').strip() or 'texture'
            if base in name_counts:
                name_counts[base] += 1
                tex.name = f"{base}_dup{name_counts[base]}"
            else:
                name_counts[base] = 0
                tex.name = base

        # Build a simple struct chunk (the "struct" block that lists textures).
        # Keep existing behaviour: 2-byte count + 2-byte flags (legacy)
        struct_payload = struct.pack(out_endian + 'HH', len(textures), 0)
        struct_chunk = struct.pack(out_endian + 'III', CHUNK_STRUCT, len(struct_payload), target_version) + struct_payload

        body = bytearray(struct_chunk)
        for tex in textures:
            # write the raw texture chunk payload as-is (header + payload)
            # Note: tex.payload here is the payload for CHUNK_TEXTURE; we need to write header+payload
            body += struct.pack(out_endian + 'III', CHUNK_TEXTURE, len(tex.payload), target_version) + tex.payload

        # top-level zero-length extension
        body += struct.pack(out_endian + 'III', CHUNK_EXTENSION, 0, target_version)

        header = struct.pack(out_endian + 'III', CHUNK_TXD, len(body), target_version)
        path.write_bytes(header + body)
        logging.info('Saved %d textures to %s (Ver=%#x)', len(textures), path.name, target_version)


# --- Simple UI App ----------------------------------------------------------
class SimpleMergerApp:
    def __init__(self, master):
        master.title('TXD Merger — Simple')
        self.input_dir = tk.StringVar()
        self.output_file = tk.StringVar()
        self.version_choice = tk.StringVar(value='Detect')  # Detect, III, VC, SA

        frame = ttk.Frame(master, padding=10)
        frame.grid(sticky='nsew')

        ttk.Label(frame, text='1) Select folder with TXD files').grid(row=0, column=0, sticky='w')
        ttk.Button(frame, text='Select Folder', command=self.select_folder, width=18).grid(row=0, column=1, sticky='e')

        ttk.Label(frame, text='2) Choose output base file').grid(row=1, column=0, sticky='w')
        ttk.Button(frame, text='Save As', command=self.select_output, width=18).grid(row=1, column=1, sticky='e')

        ttk.Label(frame, text='3) Version mode').grid(row=2, column=0, sticky='w')
        cb = ttk.Combobox(frame, textvariable=self.version_choice, values=['Detect', 'III', 'VC', 'SA'], state='readonly', width=16)
        cb.grid(row=2, column=1, sticky='e')

        self.progress = ttk.Progressbar(frame, orient='horizontal', length=380, mode='determinate')
        self.progress.grid(row=3, column=0, columnspan=2, pady=8)

        ttk.Button(frame, text='Merge', command=self.merge, width=18).grid(row=4, column=0, pady=6)
        ttk.Button(frame, text='Quit', command=master.quit, width=18).grid(row=4, column=1, pady=6)

        self.log = tk.Text(frame, height=10, width=58, state='disabled')
        self.log.grid(row=5, column=0, columnspan=2, pady=(6, 0))

        frame.columnconfigure(0, weight=1)

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
            self._log(f"Selected folder: {d}")

    def select_output(self):
        f = filedialog.asksaveasfilename(defaultextension='.txd', filetypes=[('TXD Files', '*.txd')])
        if f:
            self.output_file.set(f)
            self._log(f"Output file base: {f}")

    def merge(self):
        in_dir = Path(self.input_dir.get())
        out_base = Path(self.output_file.get()) if self.output_file.get() else None

        if not in_dir.exists() or not in_dir.is_dir():
            messagebox.showerror('Error', 'Please select a valid input folder containing TXD files.')
            return
        txd_paths = list(in_dir.glob('*.txd'))
        if not txd_paths:
            messagebox.showerror('Error', 'No .txd files found in selected folder.')
            return
        if not out_base:
            messagebox.showerror('Error', 'Please choose an output file (Save As).')
            return

        self.progress['maximum'] = len(txd_paths)
        self.progress['value'] = 0
        self._log(f"Found {len(txd_paths)} TXD files. Starting load...")

        txds = []
        failures = []

        with ThreadPoolExecutor() as exe:
            futures = {exe.submit(TxdFile().load, p): p for p in txd_paths}
            for fut in as_completed(futures):
                p = futures[fut]
                try:
                    txd = fut.result()
                    txds.append((p, txd))
                    self._log(f"Loaded: {p.name} -> game={txd.game} ver={txd.version:#x} endian={'LE' if txd.endian=='<' else 'BE'} ({len(txd.textures)} textures)")
                except Exception as e:
                    failures.append((p, str(e)))
                    self._log(f"Failed to load {p.name}: {e}")
                finally:
                    self.progress.step()

        if not txds:
            messagebox.showerror('Error', 'No valid TXD files loaded.')
            return

        # Decide grouping / target versions
        mode = self.version_choice.get()
        groups = {}
        if mode == 'Detect':
            for _, txd in txds:
                key = (txd.game, txd.version)
                groups.setdefault(key, []).append(txd)
            self._log(f"Grouping by detected game+version: {len(groups)} group(s).")
        else:
            # force everything into chosen target version
            target_ver = TARGET_VERSION_BY_GAME.get(mode, TARGET_VERSION_BY_GAME['SA'])
            groups = {('FORCED', target_ver): [txd for _, txd in txds]}
            self._log(f"Forcing merge target version: {mode} (ver={target_ver:#x})")

        out_paths = []
        for (game, ver), group in groups.items():
            merged = TxdFile()
            merged.version = ver
            merged.game = game
            # flatten textures
            merged.textures = [tex for txd in group for tex in txd.textures]

            # build output filename
            if mode == 'Detect':
                out_name = f"{out_base.stem}_{game}_ver{ver:#x}{out_base.suffix}"
            else:
                out_name = f"{out_base.stem}_merged_ver{ver:#x}{out_base.suffix}"
            out_path = out_base.with_name(out_name)
            try:
                merged.save(out_path, ver)
                out_paths.append(out_path)
                self._log(f"Saved {out_path.name} ({len(merged.textures)} textures, ver={ver:#x})")
            except Exception as e:
                self._log(f"Failed to save {out_path}: {e}")

        if failures:
            self._log(f"{len(failures)} files failed to load. See log above.")
        else:
            self._log("All files loaded successfully.")

        messagebox.showinfo('Done', f'Merge complete — {len(out_paths)} output(s) created. Check log for details.')


# --- Run --------------------------------------------------------------------
if __name__ == '__main__':
    root = tk.Tk()
    SimpleMergerApp(root)
    root.mainloop()

