# Universal TXD Merger — README

## Overview

**Universal TXD Merger** is a cross-platform Python tool to parse, merge, deduplicate, and export textures from RenderWare `*.txd` files. It supports many RenderWare variants used by games such as **Grand Theft Auto (III/VC/SA)**, **Sonic the Hedgehog (GameCube)**, **Manhunt**, **Bully**, and other PS2/PC/Xbox/GC RenderWare-based titles.

This tool focuses on merging *many* `.txd` files into one or more merged TXDs while preserving texture payloads and metadata, resolving name collisions, and deduplicating identical textures. It also optionally decodes common texture formats and exports textures as PNG (or PPM when Pillow is unavailable) for verification/preview.

---

## Key features

* Robust recursive TXD chunk parser supporting nested RenderWare chunk trees.
* Automatic RW version and platform heuristic detection (PC / PS2 / Xbox / GameCube variants).
* Content-based deduplication (MD5 of raw texture chunk bytes).
* Multiple merge policies to control how duplicates and collisions are handled:

  * `keep_first` — keep the first occurrence (default)
  * `keep_last` — later files override earlier ones
  * `skip_duplicates` — skip exact binary duplicates
  * `auto_rename` — auto-rename colliding textures and update internal payload names where possible
* Preserves `txd_texture_data` and `txd_extra_info` payloads and mipmap chains verbatim.
* Exports decoded textures to PNG (if Pillow is installed) or PPM as fallback.
* Built-in pure-Python decoders for common compressed formats: **DXT1**, **DXT3**, **DXT5**.
* Threaded, parallel loading of input `.txd` files for speed.
* Minimal Tkinter GUI: folder selection, output path, version override, endianness choice, merge policy selection, progress and logging panel.

---

## Requirements

* Python **3.10+** (3.8+ may work but 3.10+ recommended)
* Optional: **Pillow** for PNG export

Install Pillow (optional) with:

```bash
pip install pillow
```

No other external libraries are required. The DXT decoders are included in pure Python.

---

## Files

* `txd_merger_universal_with_export.py` — main script (single-file). Run this to launch the GUI.
* `README.md` — this file.

---

## Quick start (GUI)

1. Place your `.txd` files in a single folder (or multiple runs with different folders).
2. Run the script:

```bash
python txd_merger_universal_with_export.py
```

3. In the GUI:

   * Click **Select Folder** and pick the folder containing `.txd` files.
   * Click **Save As** and choose the output `.txd` base filename (the tool will append `_SA_ver0x...` or similar when using detection).
   * Choose **Version mode**: `Detect` (auto) or force a specific target version (III/VC/SA/etc.).
   * Choose **Output endianness**: `LE` (default PC-style) or `BE`.
   * Choose **Merge policy** (see options above).
   * Click **Merge**. Progress and logs will appear in the panel below.

4. After successful merge, use **Export Textures (Merged)** to export decoded textures from the last merged TXD.

   * Pick an output directory. PNG files are produced if Pillow is installed; otherwise PPMs are created.

---

## Command-line usage (manual runs)

The script is primarily GUI-driven, but you can run it from a terminal to start the app. Future CLI options may be added. Example:

```bash
python txd_merger_universal_with_export.py
```

---

## Merge policy details

* **keep\_first** (default): Keeps the first encountered texture in the input ordering. Binary-identical duplicates are deduplicated by MD5. If different textures share the same name, the tool will attempt to give the later one a safe suffix to avoid runtime collisions but keep the first's content.

* **keep\_last**: If multiple textures share a name or represent different content, the last encountered (by file load order) wins — previous ones are overridden.

* **skip\_duplicates**: Exact binary duplicates (same MD5) are omitted from the merged TXD.

* **auto\_rename**: Different content with the same textual name will be renamed (e.g. `texture_01`, `texture_02`) and the tool attempts to update the internal `texture_name` field inside the `txd_texture_data` payload where a `CHUNK_STRUCT` is present.

Choose the policy that matches your workflow. If you want to retain all textures regardless of names, use `auto_rename` to ensure no collisions.

---

## Exported texture decoding

The tool attempts to parse the internal `txd_texture_data` struct to discover:

* `d3d_format` (FourCC or small numeric codes)
* `width`, `height`, `depth`, `mipmap_count`
* raw `data` (base mipmap) and subsequent mipmaps

Currently supported decode targets:

* `DXT1`, `DXT3`, `DXT5` (FourCC / common PC compressed formats)
* Uncompressed `RGBA32` and `RGB24`

**Limitations:**

* PS2 palette-based (8-bit indexed) textures and console-specific swizzled layouts are not automatically converted. The tool preserves their bytes verbatim in merged TXDs — you can extend it to decode palettes if needed.
* Some edge-case mipmap layouts or nonstandard vendor encodings may not decode perfectly with the built-in decoders.

If a decode fails, the tool logs the error and skips exporting that texture.

---

## Output format and endianness

* By default the merger writes a **little-endian (LE)** TXD suitable for PC-style RenderWare (D3D9/PC). You may choose `BE` in the UI to write a big-endian top-level file (useful for some console-targeted workflows), but note:

  * The tool preserves nested payload bytes verbatim unless it explicitly updates an inner `texture_name` field during `auto_rename`.
  * Generating fully platform-correct console TXDs (with PS2-specific structs, sky-mipmap blocks, or swizzled surfaces) requires additional platform-specific serializers and is out of scope for the initial release.

---

## Known limitations & caveats

* **Exact dedupe only:** Deduplication uses MD5 of the raw texture chunk bytes. Visually identical textures with different encodings will not be deduped.
* **PS2/Xbox/GC platform conversions:** The tool does not automatically convert or swizzle textures between platforms. Merging PS2 TXDs into PC TXDs will preserve raw payloads but not convert palette or swizzle formats.
* **Name update heuristics:** Updating the internal `texture_name` is attempted only if a `CHUNK_STRUCT` with an expected structure is found. This is a best-effort operation; it will not always succeed for every format.
* **DXT decoder:** The included DXT decoders are pure Python and work for common blocks; rare or corrupted textures can fail decoding.

If you need any of the advanced conversions (PS2 palette -> RGBA, xbox swizzle/un-swizzle, full platform serializers), I can add them as follow-ups.

---

## Troubleshooting

* **No textures exported / decode fails:** Check the log panel. If the format is a PS2 indexed palette or unusual FourCC, decoding may fail. Provide a sample TXD and I can inspect/extend the decoder.
* **Large TXD files crash / memory pressure:** The tool loads texture payloads into memory. For thousands of large textures, consider batching or extending the tool to stream and process incrementally.
* **Name update didn't take effect:** Some TXDs store names in uncommon locations. The tool attempts the common `CHUNK_STRUCT` offset; if your files differ, paste a small hex dump and I can add support.

---

## Development notes (for contributors)

* The parser is implemented around `TxdFile.parse_chunks()` which yields `(cid, ver, payload, pos, total)` for nested scanning.
* `TxdFile.find_texture_chunks()` performs stack-based traversal to locate `CHUNK_TEXTURE` entries.
* Textures are represented by small objects holding `raw_chunk`, `payload`, `name`, and `hash`.
* The save routine assembles a basic TXD with a `CHUNK_STRUCT` (count), the `CHUNK_TEXTURE` items, then a zero-length `CHUNK_EXTENSION`.
* Add new platform-specific serializers by implementing an export path that reconstructs platform-specific `txd_texture_data` layout and performs required alignment/padding.

---

## Example workflow

1. Put a batch of `.txd` files into `input_txds/`.
2. Run the app, select `input_txds/`, choose `output.txd` as base name, `Detect` version, `LE` endianness, and set policy to `auto_rename`.
3. Click **Merge** — results will be saved next to your chosen base name with suffixes indicating detected platform/version.
4. Click **Export Textures (Merged)** and pick `output_textures/` to get PNG previews.

---

## License

This tool is provided under the MIT License (feel free to copy, modify, and redistribute). No warranty; use at your own risk.

---

## Contact / Next steps

If you want any of these next upgrades:

* **PS2 palette decoding** (indexed -> RGBA)
* **Xbox/GameCube swizzle/unswizzle**
* **Platform-aware TXD writer** (PS2/Xbox/GC tailored output)
* **CLI / batch automation**
* **Unit tests and sample TXDs**

Tell me which you'd like and I’ll add them. Enjoy merging!

---

# Update Log

**v0.1 — 2025-08-19**

* Initial prototype: basic TXD parser + simple merge UI (folder select, save as, version detect/override).
* Implements recursive chunk parsing and texture extraction.

**v0.2 — 2025-08-19**

* Improved deduplication by MD5 on raw texture chunks.
* Added endianness detection and grouping by detected game/version.
* Name-collision handling (automatic suffixing when necessary).

**v0.3 — 2025-08-19**

* Added parallel loading of TXD files (ThreadPoolExecutor) for large folders.
* Preserved nested texture payloads and extra info blocks when saving.

**v0.4 — 2025-08-19**

* Implemented merge policy options: `keep_first`, `keep_last`, `skip_duplicates`, `auto_rename`.
* Added PNG/PPM export of decoded textures (Pillow optional).
* Bundled pure-Python DXT1/DXT3/DXT5 decoders for preview export.

**v0.5 — 2025-08-19**

* Added robust UI controls: output endianness, version forcing, merge policy dropdown, export button.
* README and documentation added.
* Minor bug fixes and improved logging.

*Notes:* dates reflect the current development snapshot. Future updates will include platform-aware serializers (PS2/Xbox/GC), palette decoding for PS2 textures, swizzle/unswizzle support, and CLI/batch automation.
