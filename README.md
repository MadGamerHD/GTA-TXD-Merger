# TXD Merger — Detailed Description & How It Works

A compact, fast TXD-merger tool (single-file Python + Tkinter) for RenderWare `.txd` texture dictionaries used by the classic GTA games.
It’s meant to be a lightweight, reliable helper that **scans a folder of TXD files, deduplicates textures, and writes one or more merged TXD files**, keeping per-file versions where possible.

---

## Supported games / platforms (what it understands)

* **GTA III, Vice City, San Andreas** (representative RenderWare versions present in those games).
* Platform heuristics included: **PC (little-endian)**, **Xbox (big-endian)**, and **PS2** (structure differences).
* The merger detects the on-disk TXD *version* and groups/merges files by that detected version. You can also **force** a target version (III, VC, or SA) to convert everything to that version tag when saving.

> Note: The tool reads and preserves each texture chunk as-is (raw chunk payloads). It does **not** attempt complex per-platform conversions (unswizzling PS2 data, or converting palette/compression formats). For cross-version/platform conversion (e.g. PC ↔ PS2/Xbox) use a dedicated tool such as **Magic.TXD** after merging the result.

---

## Key features

* **Automatic endianness detection** (PC little-endian vs Xbox big-endian) so the parser knows how to interpret headers.
* **Game/version detection**: reads the RenderWare/version field and groups TXDs by detected `(game, version)` pair.
* **Two merge modes**:

  * **Detect** (default): groups TXDs by their detected game+version and writes one merged TXD per group.
  * **Force (III / VC / SA)**: forces all input TXDs into a single merged output tagged with the chosen version.
* **Parallel parsing** using `ThreadPoolExecutor` for fast scanning of many files (scales well to large folders).
* **Content deduplication**: identical texture chunks are deduplicated using an MD5 hash of the raw chunk (so exact binary duplicates are removed).
* **Name collision handling**: if two different textures share the same name but have different content, duplicates are renamed in-memory to `name_dupN` so they don’t silently overwrite each other in the merged manifest. (Binary payloads are preserved; see Limitations below about embedding names.)
* **Minimal, beginner-friendly UI**: three-step workflow (Select Folder → Save As → Version mode → Merge). Progress bar + log window.
* **Structure dump**: examine chunk tree for the first TXD in the folder (useful for debugging and verification).
* **Safe file writes** with clear logging and success/failure messages.

---

## How the merge works (technical summary)

1. **Scan**: the tool finds `*.txd` files in the chosen input folder.
2. **Load & detect**: for each file it:

   * Detects endianness by reading header chunk ids.
   * Reads the top-level TXD header (chunk id / size / version).
   * Detects game/version from the version field.
   * Walks nested chunks to find texture (raster) chunks.
   * Extracts texture names where present (PC-style 32-byte name in `Struct` payload or fallback probe).
   * Hashes the raw texture chunk bytes (MD5) for dedupe.
3. **Group**: group loaded TXDs by `(game, version)` when in Detect mode, or put all into one group when forcing a version.
4. **Merge**:

   * Flatten textures from group(s).
   * Deduplicate by binary content (hash).
   * Resolve name collisions by renaming in-memory labels (`_dupN`).
   * Build a new TXD body consisting of one `Struct` chunk listing the texture count and a sequence of `Texture` chunks using the original raw payloads.
   * Append a top-level zero-length `Extension` chunk and header, then write the file.
5. **Output**: written files are named according to the base filename chosen by the user and annotated with the detected game/version (or `_merged_ver...` if forced).

---

## Typical usage (UX)

1. Put all `.txd` files in a single folder.
2. Run the script. Click **Select Folder** and choose the folder.
3. Click **Save As** and pick a base filename + destination.
4. Choose **Detect** (recommended) or explicitly choose `III`, `VC`, or `SA`.
5. Click **Merge** — watch the progress and log. Resulting merged files are written next to your chosen output path (one per detected group, or one forced file).

---

## Outputs & file naming

* If **Detect** mode: outputs like `base_SA_ver0x1803ffff.txd`, `base_VC_ver0x1003ffff.txd`, etc. — one per detected `(game,version)`.
* If **Force** mode: `base_merged_ver0x1803ffff.txd` (single output with the chosen target version).

---

## Limitations & important notes (read this)

* **No format conversion**: the merger preserves raw texture chunks exactly as they were in input TXDs. It does *not*:

  * Unscramble/swizzle PS2 texture texel layout.
  * Convert palette formats or change compression (DXT) formats.
  * Rebuild or rewrite the internal texture struct payloads to match a different platform (other than changing the version tag in written chunk headers).
* **Names inside binary payloads**: the tool updates only the in-memory `name` labels for collision resolution; **it does not rewrite names inside binary texture headers**. Properly changing a texture name inside a texture header requires rebuilding that texture’s `Struct` chunk and is non-trivial—this is a planned enhancement.
* **No image preview / extraction**: the tool does not extract textures to PNG/DDS — it’s focused on merging TXDs quickly and reliably.
* **Subfolders**: current simple UI scans only the selected folder (no recursive subfolder traverse).
* **PS2/Xbox specifics**: while structural differences are handled (endianness and extra strings/extensions), full PS2/Xbox-to-PC conversion (unswizzling, color order changes) is outside the scope. For conversions, use Magic.TXD or another dedicated converter after merging.
* **Validation**: merged TXDs are assembled using your original payloads; they will be valid TXDs in many cases, but **you should verify results** with tools like Magic.TXD, RW Analyze, or your workflow (import into the game editor or convert and test).
* **Beta status**: the tool is a beta-grade merger with robust parsing and fast performance but not yet feature-complete for full format conversions.

---

## Recommended workflow for cross-version needs

1. Use this merger to produce a single clean SA/VC/III TXD (as appropriate).
2. If you need a different target platform/format, run the merged TXD through **Magic.TXD** (or similar) to convert platform-specific details (unswizzle PS2, convert compression flags, fix names in headers, etc.).
3. Test the final TXD in your target editor/game.

---

## Future/optional improvements (planned)

* Option to **export textures to DDS/PNG** for verification.
* Rewriting texture `Struct` payloads so renaming writes into the merged binary (proper header rebuild).
* Recursive folder scanning and CLI (headless) mode for automation.
* Faster large-batch tuning (threadpool size config) and a manifest file mapping source→merged textures.
* Optional integration with Magic.TXD-like conversion steps or a small helper script to call Magic.TXD automatically (if installed).

---

## Performance & footprint

* Lightweight single-file script (small footprint). Parsing is parallelized and optimized for large folders — merging thousands of TXDs is feasible (your reported tests show sub-second/seconds behavior on many machines, but speed depends on disk I/O and CPU).

---

## Troubleshooting & verification

* If a merged TXD fails in your target:

  * Open the merged file in **Magic.TXD** or **RW Analyze** to inspect chunk tree and headers.
  * If PS2 textures look scrambled, their data is likely swizzled — you’ll need platform conversion.
  * Verify texture names and counts using the structure dump option in the tool (writes a structure text file for inspection).
* Start testing with a small subset of TXDs (2–10 files) before running very large batches.
