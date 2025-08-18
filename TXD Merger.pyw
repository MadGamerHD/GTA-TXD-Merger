#!/usr/bin/env python3
"""
TXD Merger — Simple UI
- Minimal UI: Select Folder, Save As, Version selector (Detect / III / VC / SA), Merge.
- Preserves robust parsing: endian detection, version detection, duplicate-content dedupe,
  name-collision handling (in-memory labels), parallel loading for speed.
"""

import struct, hashlib, logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# --- Config / constants -----------------------------------------------------
CHUNK_TXD       = 0x16
CHUNK_STRUCT    = 0x01
CHUNK_TEXTURE   = 0x15
CHUNK_EXTENSION = 0x03

# Known version markers (used for detection). We pick representative values.
GAME_VERSIONS = {
    'III': [0x00000310, 0x0003FFFF],
    'VC':  [0x1003FFFF, 0x0C02FFFF],
    'SA':  [0x1803FFFF],
}
# Representative target version to write when forcing a platform
TARGET_VERSION_BY_GAME = {
    'III': 0x00000310,
    'VC':  0x1003FFFF,
    'SA':  0x1803FFFF,
}

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
        end = len(data) if length is None else offset + length
        pos = offset
        header_fmt = endian + 'III'
        header_size = 12
        while pos + header_size <= end:
            try:
                cid, size, ver = struct.unpack_from(header_fmt, data, pos)
            except struct.error:
                break
            total = header_size + size
            if size < 0 or pos + total > end:
                logging.warning('Invalid/overflow chunk at pos %d (cid=%#x)', pos, cid)
                break
            chunk = data[pos:pos + total]
            payload = chunk[header_size:]
            yield cid, ver, payload, pos, total
            pos += total

    @staticmethod
    def detect_game_from_version(v: int) -> str:
        for game, versions in GAME_VERSIONS.items():
            if v in versions:
                return game
        try:
            min_all = min(min(vs) for vs in GAME_VERSIONS.values())
            if v < min_all:
                return 'III'
            if v < min(GAME_VERSIONS['SA']):
                return 'VC'
        except Exception:
            pass
        return 'SA'

    @staticmethod
    def find_texture_chunks(data: bytes, endian: str = '<'):
        stack = [data]
        while stack:
            blk = stack.pop()
            for cid, ver, payload, pos, total in TxdFile.parse_chunks(blk, 0, None, endian):
                if cid == CHUNK_TEXTURE:
                    yield ver, payload, blk, pos, total
                else:
                    stack.append(payload)

    @staticmethod
    def extract_name(chunk_payload: bytes, endian: str = '<') -> str | None:
        for cid, ver, payload, _, _ in TxdFile.parse_chunks(chunk_payload, 0, None, endian):
            if cid == CHUNK_STRUCT and len(payload) >= 40:
                raw_name = payload[8:40]
                return raw_name.split(b"\x00", 1)[0].decode('ascii', 'ignore')
        try:
            raw = chunk_payload[:256]
            return raw.split(b'\x00', 1)[0].decode('ascii', 'ignore')[:32]
        except Exception:
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
            raise ValueError(f"{path.name} is not a valid TXD (cid={cid})")

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
            name = TxdFile.extract_name(tex_payload, endian=self.endian)
            if name:
                textures.append(Texture(name, raw_chunk, tex_payload))

        self.textures = textures
        logging.info('Loaded %d textures from %s (Game=%s, Ver=%#x, endian=%s)',
                     len(textures), path.name, self.game, version, 'LE' if self.endian == '<' else 'BE')
        return self

    def save(self, path: Path, target_version: int) -> None:
        # Deduplicate by content hash
        hash_map = {}
        for tex in self.textures:
            if tex.hash not in hash_map:
                hash_map[tex.hash] = tex

        textures = list(hash_map.values())

        # Resolve duplicate names (same name but different content)
        name_counts = {}
        for tex in textures:
            base = tex.name or 'texture'
            if base in name_counts:
                name_counts[base] += 1
                tex.name = f"{base}_dup{name_counts[base]}"
            else:
                name_counts[base] = 0

        # Build struct chunk like before
        struct_payload = struct.pack('<HH', len(textures), 0)
        struct_chunk = struct.pack('<III', CHUNK_STRUCT, len(struct_payload), target_version) + struct_payload

        body = bytearray(struct_chunk)
        for tex in textures:
            body += struct.pack('<III', CHUNK_TEXTURE, len(tex.payload), target_version) + tex.payload

        # top-level zero-length extension
        body += struct.pack('<III', CHUNK_EXTENSION, 0, target_version)

        header = struct.pack('<III', CHUNK_TXD, len(body), target_version)
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
        self.log.grid(row=5, column=0, columnspan=2, pady=(6,0))

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
