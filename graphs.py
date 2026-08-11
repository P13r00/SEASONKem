import os
import matplotlib.colors as mcolors
import matplotlib.pyplot as plt
import numpy as np

# =============================================================================
# 1. DATA CONFIGURATION SECTION
# =============================================================================

# --- AEAD DATA ---
AEAD_SIZES = [16, 64, 128, 256, 1024]

AEAD_DATA = [
    {
        "name": "ChaCha20-Poly1305",
        "flash": 8592,  # bytes
        "stack_hwm": 624,  # bytes
        "heap_peak": [144, 288, 480, 864, 3168],  # bytes at 16, 64, 128, 256, 1024
        "cycles_enc": [11864, 12349, 17625, 28177, 91489],
        "cycles_dec": [12105, 12591, 17868, 28419, 91731],
    },
    {
        "name": "AES-192-GCM",
        "flash": 22676,  # bytes
        "stack_hwm": 1300,  # bytes
        "heap_peak": [136, 280, 472, 856, 3160],  # bytes at 16, 64, 128, 256, 1024
        "cycles_enc": [18584, 26861, 37898, 59973, 192418],
        "cycles_dec": [19967, 32159, 48416, 80931, 276016],
    },
    {
        "name": "AES-256-GCM",
        "flash": 22672,  # bytes
        "stack_hwm": 1300,  # bytes
        "heap_peak": [144, 288, 480, 864, 3168],  # bytes at 16, 64, 128, 256, 1024
        "cycles_enc": [19414, 28238, 40004, 63536, 204724],
        "cycles_dec": [20797, 33536, 50522, 84494, 288322],
    },
    {
        "name": "Schwaemm128-128",
        "flash": 20840,  # bytes
        "stack_hwm": 428,  # bytes
        "heap_peak": [128, 272, 464, 848, 3152],  # bytes at 16, 64, 128, 256, 1024
        "cycles_enc": [3350, 5292, 7848, 12960, 43631],
        "cycles_dec": [3512, 5775, 8766, 14750, 50654],
    },
    {
        "name": "Schwaemm192-192",
        "flash": 19768,  # bytes
        "stack_hwm": 420,  # bytes
        "heap_peak": [152, 296, 488, 872, 3176],  # bytes at 16, 64, 128, 256, 1024
        "cycles_enc": [5072, 6934, 9691, 14382, 44178],
        "cycles_dec": [5286, 7163, 9928, 14642, 44562],
    },
    {
        "name": "Schwaemm256-256",
        "flash": 20900,  # bytes
        "stack_hwm": 432,  # bytes
        "heap_peak": [176, 320, 512, 896, 3200],  # bytes at 16, 64, 128, 256, 1024
        "cycles_enc": [7262, 8972, 12324, 19028, 59251],
        "cycles_dec": [7564, 9296, 12666, 19405, 59845],
    },
    {
        "name": "Ascon-AEAD128",
        "flash": 15116,  # bytes
        "stack_hwm": 400,  # bytes
        "heap_peak": [128, 272, 464, 848, 3152],  # bytes at 16, 64, 128, 256, 1024
        "cycles_enc": [5908, 8835, 12740, 20548, 67396],
        "cycles_dec": [6089, 9102, 13117, 21149, 69341],
    },
    {
        "name": "Ascon80pq",
        "flash": 15460,  # bytes
        "stack_hwm": 408,  # bytes
        "heap_peak": [136, 280, 472, 956, 3160],  # bytes at 16, 64, 128, 256, 1024
        "cycles_enc": [5967, 8895, 12798, 20606, 67454],
        "cycles_dec": [6155, 9167, 13183, 21215, 69407],
    },
    {
        "name": "Xoodyak-AEAD",
        "flash": 7976,  # bytes
        "stack_hwm": 392,  # bytes
        "heap_peak": [128, 272, 464, 848, 3152],  # bytes at 16, 64, 128, 256, 1024
        "cycles_enc": [3050, 4850, 7541, 12067, 40930],
        "cycles_dec": [3195, 5063, 7845, 12558, 42542],
    },
]

# --- HASH DATA ---
HASH_DATA = [
    {
        "name": "SHA3-256",
        "flash": 12044,
        "stack_hwm": 456,
        "heap_peak": 168,
        "cycles": 11001,  # cycles for outputting 32 bytes
    },
    {
        "name": "ESCH256",
        "flash": 17912,
        "stack_hwm": 308,
        "heap_peak": 168,
        "cycles": 10644,  # cycles for outputting 32 bytes
    },
    {
        "name": "ESCH384",
        "flash": 17960,
        "stack_hwm": 320,
        "heap_peak": 184,
        "cycles": 20370,  # cycles for outputting 32 bytes
    },
    {
        "name": "ASCON-Hash256",
        "flash": 12284,
        "stack_hwm": 288,
        "heap_peak": 168,
        "cycles": 16902,  # cycles for outputting 32 bytes
    },
    {
        "name": "XOODYAK",
        "flash": 7056,
        "stack_hwm": 280,
        "heap_peak": 168,
        "cycles": 9359,  # cycles for outputting 32 bytes
    },
]

# --- KEM DATA ---
KEM_DATA = [
    {
        "name": "ML-KEM-512",
        "flash": 26780,
        "stack_hwm": 5580,
        "heap_peak": 3264,
        "cycles_keygeneration": 373999,
        "cycles_encapsulation": 371631,
        "cycles_decapsulation": 405922,
    },
    {
        "name": "ML-KEM-768",
        "flash": 26836,
        "stack_hwm": 6612,
        "heap_peak": 4736,
        "cycles_keygeneration": 610954,
        "cycles_encapsulation": 624819,
        "cycles_decapsulation": 669922,
    },
    {
        "name": "X-Wing",
        "flash": 33920,
        "stack_hwm": 6876,
        "heap_peak": 4864,
        "cycles_keygeneration": 1174391,
        "cycles_encapsulation": 1763899,
        "cycles_decapsulation": 1245562,
    },
    {
        "name": "Season 0",
        "flash": 33864,
        "stack_hwm": 5844,
        "heap_peak": 3392,
        "cycles_keygeneration": 937504,
        "cycles_encapsulation": 1510780,
        "cycles_decapsulation": 981632,
    },
    {
        "name": "Spring",
        "flash": 37376,
        "stack_hwm": 5844,
        "heap_peak": 3392,
        "cycles_keygeneration": 937475,
        "cycles_encapsulation": 1509109,
        "cycles_decapsulation": 979961,
    },
    {
        "name": "Summer",
        "flash": 42688,
        "stack_hwm": 5844,
        "heap_peak": 3392,
        "cycles_keygeneration": 937458,
        "cycles_encapsulation": 1516637,
        "cycles_decapsulation": 987489,
    },
    {
        "name": "Autumn",
        "flash": 48224,
        "stack_hwm": 5844,
        "heap_peak": 3392,
        "cycles_keygeneration": 937548,
        "cycles_encapsulation": 1510463,
        "cycles_decapsulation": 981315,
    },
    {
        "name": "Winter",
        "flash": 48312,
        "stack_hwm": 6740,
        "heap_peak": 4864,
        "cycles_keygeneration": 1174707,
        "cycles_encapsulation": 1773919,
        "cycles_decapsulation": 1255445,
    },
]

# --- KEM x AEAD FLASH COMBINATION MATRIX (in Bytes) ---
KEM_AEAD_FLASH = {
    "X-Wing": {
        "AES-192": 54620,
        "AES-256": 54612,
        "Ascon-128": 47052,
        "Ascon-80pq": 47396,
        "ChaCha20": 40532,
        "Sparkle-128": 52868,
        "Sparkle-192": 51796,
        "Sparkle-256": 52924,
        "Xoodyak": 39916,
    },
    "Season 0": {
        "AES-192": 54564,
        "AES-256": 54564,
        "Ascon-128": 47004,
        "Ascon-80pq": 47348,
        "ChaCha20": 40484,
        "Sparkle-128": 52812,
        "Sparkle-192": 51740,
        "Sparkle-256": 52868,
        "Xoodyak": 39860,
    },
    "Spring": {
        "AES-192": 58068,
        "AES-256": 58068,
        "Ascon-128": 50516,
        "Ascon-80pq": 50860,
        "ChaCha20": 43988,
        "Sparkle-128": 56316,
        "Sparkle-192": 55244,
        "Sparkle-256": 56380,
        "Xoodyak": 40340,
    },
    "Summer": {
        "AES-192": 63388,
        "AES-256": 63380,
        "Ascon-128": 47876,
        "Ascon-80pq": 48220,
        "ChaCha20": 49300,
        "Sparkle-128": 61636,
        "Sparkle-192": 60564,
        "Sparkle-256": 61692,
        "Xoodyak": 48684,
    },
    "Autumn": {
        "AES-192": 68924,
        "AES-256": 68916,
        "Ascon-128": 61356,
        "Ascon-80pq": 61700,
        "ChaCha20": 54836,
        "Sparkle-128": 53052,
        "Sparkle-192": 51980,
        "Sparkle-256": 53108,
        "Xoodyak": 54220,
    },
    "Winter": {
        "AES-192": 69004,
        "AES-256": 69004,
        "Ascon-128": 61452,
        "Ascon-80pq": 61796,
        "ChaCha20": 54924,
        "Sparkle-128": 53132,
        "Sparkle-192": 52060,
        "Sparkle-256": 53196,
        "Xoodyak": 54308,
    },
}

OUTPUT_DIR = "benchmark_graphs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

plt.rcParams.update({
    "font.size": 12,
    "font.family": "sans-serif",
    "axes.labelsize": 14,
    "axes.titlesize": 16,
    "legend.fontsize": 11,
    "xtick.labelsize": 12,
    "ytick.labelsize": 12,
    "figure.dpi": 300,
})


def save_plot(filename):
    filepath = os.path.join(OUTPUT_DIR, filename)
    plt.tight_layout()
    plt.savefig(filepath, format="png", bbox_inches="tight")
    plt.close()
    print(f"Saved: {filepath}")


# =============================================================================
# 2. IMAGE TABLE RENDERING HELPERS
# =============================================================================


def format_cell(val, base_val):
    """Formats raw value alongside percentage gap from baseline."""
    if base_val == 0:
        return f"{val:,}\n(0.00%)"
    gap = ((val - base_val) / base_val) * 100
    sign = "+" if gap > 0 else ""
    return f"{val:,}\n({sign}{gap:.2f}%)"


def save_table_as_image(title, headers, rows, filename):
    """Renders a tabular dataset directly to a high-resolution PNG image."""
    fig_width = max(10, len(headers) * 2.2)
    fig_height = len(rows) * 0.65 + 1.8

    fig, ax = plt.subplots(figsize=(fig_width, fig_height))
    ax.axis("tight")
    ax.axis("off")

    table = ax.table(
        cellText=rows, colLabels=headers, loc="center", cellLoc="center"
    )
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.0, 1.8)

    # Style Table Header and Alternating Rows
    for (row_idx, col_idx), cell in table.get_celld().items():
        if row_idx == 0:
            cell.set_facecolor("#1f77b4")
            cell.set_text_props(weight="bold", color="white")
        else:
            if row_idx % 2 == 0:
                cell.set_facecolor("#f8f9fa")
            else:
                cell.set_facecolor("#ffffff")

    plt.title(title, fontsize=14, pad=15, weight="bold")
    save_plot(filename)


def plot_kem_aead_flash_table():
    """Generates an annotated color-coded heatmap table image showing Flash

    memory size (Bytes) across KEMs (Rows) and AEADs (Columns).
    """
    rows_kems = list(KEM_AEAD_FLASH.keys())
    cols_aeads = list(next(iter(KEM_AEAD_FLASH.values())).keys())

    # Build 2D Matrix
    matrix = np.array(
        [[KEM_AEAD_FLASH[kem][aead] for aead in cols_aeads] for kem in rows_kems]
    )

    fig, ax = plt.subplots(figsize=(14, 7))

    # Colormap: RdYlGn_r (Green=Low Flash Memory, Red=High Flash Memory)
    cmap = plt.get_cmap("RdYlGn_r")
    norm = mcolors.Normalize(vmin=matrix.min(), vmax=matrix.max())

    im = ax.imshow(matrix, cmap=cmap, norm=norm, aspect="auto")

    # Add Colorbar Legend
    cbar = fig.colorbar(im, ax=ax, pad=0.02)
    cbar.set_label(
        "Flash Size (Bytes)", rotation=270, labelpad=20, weight="bold"
    )

    # Set Axis Labels
    ax.set_xticks(np.arange(len(cols_aeads)))
    ax.set_yticks(np.arange(len(rows_kems)))
    ax.set_xticklabels(cols_aeads, rotation=35, ha="right", weight="bold")
    ax.set_yticklabels(rows_kems, weight="bold")

    # Clean borders and grid separation
    ax.spines[:].set_visible(False)
    ax.set_xticks(np.arange(len(cols_aeads)) - 0.5, minor=True)
    ax.set_yticks(np.arange(len(rows_kems)) - 0.5, minor=True)
    ax.grid(which="minor", color="white", linestyle="-", linewidth=2)
    ax.tick_params(which="minor", bottom=False, left=False)

    # Annotate values inside each cell with contrast text color
    for i in range(len(rows_kems)):
        for j in range(len(cols_aeads)):
            val = matrix[i, j]
            normalized_val = norm(val)
            text_color = "white" if (normalized_val > 0.75) else "black"

            ax.text(
                j,
                i,
                f"{val:,} B",
                ha="center",
                va="center",
                color=text_color,
                fontsize=10,
                weight="bold",
            )

    ax.set_title(
        "KEM Framework × AEAD Primitive: Total Flash Memory Footprint (Bytes)",
        fontsize=14,
        pad=20,
        weight="bold",
    )

    save_plot("KEM_AEAD_Flash_Matrix_Table.png")


def generate_image_tables():
    """Builds and exports all image tables."""

    # --- 1. AEAD TABLES ---
    base_aead = next(d for d in AEAD_DATA if d["name"] == "Ascon-AEAD128")

    idx_64 = 1  # 64 bytes is at index 1
    headers_aead_64 = [
        "Algorithm",
        "Flash (Bytes)",
        "Stack HWM (Bytes)",
        "Heap Peak (Bytes)",
        "Encrypt Cycles",
        "Decrypt Cycles",
    ]
    rows_aead_64 = []
    for d in AEAD_DATA:
        rows_aead_64.append([
            d["name"],
            format_cell(d["flash"], base_aead["flash"]),
            format_cell(d["stack_hwm"], base_aead["stack_hwm"]),
            format_cell(d["heap_peak"][idx_64], base_aead["heap_peak"][idx_64]),
            format_cell(
                d["cycles_enc"][idx_64], base_aead["cycles_enc"][idx_64]
            ),
            format_cell(
                d["cycles_dec"][idx_64], base_aead["cycles_dec"][idx_64]
            ),
        ])
    save_table_as_image(
        "AEAD Benchmark Table (64B Payload, vs. Ascon-AEAD128)",
        headers_aead_64,
        rows_aead_64,
        "AEAD_Table_Benchmark_64B.png",
    )

    # AEAD Memory (All Payload Sizes)
    headers_mem = ["Algorithm", "Flash (Bytes)", "Stack HWM (Bytes)"]
    rows_mem = []
    for d in AEAD_DATA:
        rows_mem.append([
            d["name"],
            format_cell(d["flash"], base_aead["flash"]),
            format_cell(d["stack_hwm"], base_aead["stack_hwm"]),
        ])
    save_table_as_image(
        "AEAD Memory Footprint (vs. Ascon-AEAD128)",
        headers_mem,
        rows_mem,
        "AEAD_Table_Memory.png",
    )

    # AEAD Heap Across Payload Sizes
    headers_size = ["Algorithm"] + [f"{s}B Payload" for s in AEAD_SIZES]
    rows_heap = []
    for d in AEAD_DATA:
        r = [d["name"]] + [
            format_cell(v, b)
            for v, b in zip(d["heap_peak"], base_aead["heap_peak"])
        ]
        rows_heap.append(r)
    save_table_as_image(
        "AEAD Heap Peak Usage Across Sizes (vs. Ascon-AEAD128)",
        headers_size,
        rows_heap,
        "AEAD_Table_Heap.png",
    )

    # AEAD Encrypt Across Payload Sizes
    rows_enc = []
    for d in AEAD_DATA:
        r = [d["name"]] + [
            format_cell(v, b)
            for v, b in zip(d["cycles_enc"], base_aead["cycles_enc"])
        ]
        rows_enc.append(r)
    save_table_as_image(
        "AEAD Encryption Cycles Across Sizes (vs. Ascon-AEAD128)",
        headers_size,
        rows_enc,
        "AEAD_Table_Speed_Encrypt.png",
    )

    # AEAD Decrypt Across Payload Sizes
    rows_dec = []
    for d in AEAD_DATA:
        r = [d["name"]] + [
            format_cell(v, b)
            for v, b in zip(d["cycles_dec"], base_aead["cycles_dec"])
        ]
        rows_dec.append(r)
    save_table_as_image(
        "AEAD Decryption Cycles Across Sizes (vs. Ascon-AEAD128)",
        headers_size,
        rows_dec,
        "AEAD_Table_Speed_Decrypt.png",
    )

    # --- 2. HASH TABLE ---
    base_hash = next(d for d in HASH_DATA if d["name"] == "SHA3-256")
    headers_hash = [
        "Algorithm",
        "Flash (Bytes)",
        "Stack HWM (Bytes)",
        "Heap Peak (Bytes)",
        "Cycles (32B Out)",
    ]
    rows_hash = []
    for d in HASH_DATA:
        rows_hash.append([
            d["name"],
            format_cell(d["flash"], base_hash["flash"]),
            format_cell(d["stack_hwm"], base_hash["stack_hwm"]),
            format_cell(d["heap_peak"], base_hash["heap_peak"]),
            format_cell(d["cycles"], base_hash["cycles"]),
        ])
    save_table_as_image(
        "HASH Benchmark Table (vs. SHA3-256)",
        headers_hash,
        rows_hash,
        "HASH_Table_Benchmark.png",
    )

    # --- 3. KEM TABLE ---
    base_kem = next(d for d in KEM_DATA if d["name"] == "X-Wing")
    headers_kem = [
        "Algorithm",
        "Flash (Bytes)",
        "Stack HWM (Bytes)",
        "Heap Peak (Bytes)",
        "KeyGeneration Cycles",
        "Encapsulation Cycles",
        "Decapsulation Cycles",
    ]
    rows_kem = []
    for d in KEM_DATA:
        rows_kem.append([
            d["name"],
            format_cell(d["flash"], base_kem["flash"]),
            format_cell(d["stack_hwm"], base_kem["stack_hwm"]),
            format_cell(d["heap_peak"], base_kem["heap_peak"]),
            format_cell(d["cycles_keygeneration"], base_kem["cycles_keygeneration"]),
            format_cell(d["cycles_encapsulation"], base_kem["cycles_encapsulation"]),
            format_cell(d["cycles_decapsulation"], base_kem["cycles_decapsulation"]),
        ])
    save_table_as_image(
        "KEM Benchmark Table (vs. X-Wing)",
        headers_kem,
        rows_kem,
        "KEM_Table_Benchmark.png",
    )


# =============================================================================
# 3. LATEX TABLE GENERATOR HELPER
# =============================================================================


def format_cell_latex(val, base_val):
    """Formats cell values for LaTeX tables with properly escaped % signs."""
    if base_val == 0:
        return f"{val:,} (0.00\\%)"
    gap = ((val - base_val) / base_val) * 100
    sign = "+" if gap > 0 else ""
    return f"{val:,} ({sign}{gap:.2f}\\%)"


def build_latex_table(caption, label, headers, rows, footnote=None):
    """Generates LaTeX code following the adjustwidth + tabularx template."""
    num_cols = len(headers)
    col_spec = "C" * num_cols

    headers_formatted = (
        " & ".join([f"\\textbf{{{h}}}" for h in headers]) + " \\\\"
    )

    rows_formatted = []
    for r in rows:
        rows_formatted.append(" & ".join(r) + " \\\\")

    table_body = "\n            \\midrule\n            ".join(rows_formatted)

    latex = f"""\\begin{{table}}[H]
\\caption{{{caption}\\label{{{label}}}}}
    \\begin{{adjustwidth}}{{-\\extralength}}{{0cm}}
        \\begin{{tabularx}}{{\\fulllength}}{{{col_spec}}}
            \\toprule
            {headers_formatted}
            \\midrule
            {table_body}
            \\bottomrule
    \\end{{tabularx}}
    \\end{{adjustwidth}}"""

    if footnote:
        latex += f"""
    \\vspace{{2pt}}
    \\noindent{{\\footnotesize{{{footnote}}}}}"""

    latex += "\n\\end{table}\n"
    return latex


def generate_latex_tables():
    """Generates and writes all benchmark tables in LaTeX format to a .txt file."""
    output_filepath = os.path.join(OUTPUT_DIR, "benchmark_tables.txt")
    latex_blocks = []

    # --- 1. AEAD 64B SUMMARY TABLE ---
    base_aead = next(d for d in AEAD_DATA if d["name"] == "Ascon-AEAD128")
    idx_64 = 1
    headers_aead_64 = [
        "Algorithm",
        "Flash (Bytes)",
        "Stack HWM",
        "Heap Peak",
        "Encrypt Cycles",
        "Decrypt Cycles",
    ]
    rows_aead_64 = []
    for d in AEAD_DATA:
        rows_aead_64.append([
            d["name"],
            format_cell_latex(d["flash"], base_aead["flash"]),
            format_cell_latex(d["stack_hwm"], base_aead["stack_hwm"]),
            format_cell_latex(
                d["heap_peak"][idx_64], base_aead["heap_peak"][idx_64]
            ),
            format_cell_latex(
                d["cycles_enc"][idx_64], base_aead["cycles_enc"][idx_64]
            ),
            format_cell_latex(
                d["cycles_dec"][idx_64], base_aead["cycles_dec"][idx_64]
            ),
        ])
    latex_blocks.append(
        build_latex_table(
            caption=(
                "AEAD Benchmark Performance and Memory Footprint (64 Bytes"
                " Payload)."
            ),
            label="tab:aead_64b_benchmark",
            headers=headers_aead_64,
            rows=rows_aead_64,
            footnote=(
                "Comparisons expressed as percentage deviation relative to"
                " Ascon-AEAD128."
            ),
        )
    )

    # --- 2. AEAD MEMORY FOOTPRINT TABLE ---
    headers_mem = ["Algorithm", "Flash (Bytes)", "Stack HWM (Bytes)"]
    rows_mem = []
    for d in AEAD_DATA:
        rows_mem.append([
            d["name"],
            format_cell_latex(d["flash"], base_aead["flash"]),
            format_cell_latex(d["stack_hwm"], base_aead["stack_hwm"]),
        ])
    latex_blocks.append(
        build_latex_table(
            caption="AEAD Static and Stack Memory Footprint.",
            label="tab:aead_memory",
            headers=headers_mem,
            rows=rows_mem,
            footnote="Comparisons expressed relative to Ascon-AEAD128.",
        )
    )

    # --- 3. AEAD HEAP PEAK TABLE ---
    headers_size = ["Algorithm"] + [f"{s}B Payload" for s in AEAD_SIZES]
    rows_heap = []
    for d in AEAD_DATA:
        r = [d["name"]] + [
            format_cell_latex(v, b)
            for v, b in zip(d["heap_peak"], base_aead["heap_peak"])
        ]
        rows_heap.append(r)
    latex_blocks.append(
        build_latex_table(
            caption="AEAD Heap Peak Usage across payload sizes.",
            label="tab:aead_heap",
            headers=headers_size,
            rows=rows_heap,
            footnote="Comparisons expressed relative to Ascon-AEAD128.",
        )
    )

    # --- 4. AEAD ENCRYPTION CYCLES TABLE ---
    rows_enc = []
    for d in AEAD_DATA:
        r = [d["name"]] + [
            format_cell_latex(v, b)
            for v, b in zip(d["cycles_enc"], base_aead["cycles_enc"])
        ]
        rows_enc.append(r)
    latex_blocks.append(
        build_latex_table(
            caption=(
                "AEAD Encryption execution time (cycles) across payload sizes."
            ),
            label="tab:aead_speed_enc",
            headers=headers_size,
            rows=rows_enc,
            footnote="Comparisons expressed relative to Ascon-AEAD128.",
        )
    )

    # --- 5. AEAD DECRYPTION CYCLES TABLE ---
    rows_dec = []
    for d in AEAD_DATA:
        r = [d["name"]] + [
            format_cell_latex(v, b)
            for v, b in zip(d["cycles_dec"], base_aead["cycles_dec"])
        ]
        rows_dec.append(r)
    latex_blocks.append(
        build_latex_table(
            caption=(
                "AEAD Decryption execution time (cycles) across payload sizes."
            ),
            label="tab:aead_speed_dec",
            headers=headers_size,
            rows=rows_dec,
            footnote="Comparisons expressed relative to Ascon-AEAD128.",
        )
    )

    # --- 6. HASH BENCHMARK TABLE ---
    base_hash = next(d for d in HASH_DATA if d["name"] == "SHA3-256")
    headers_hash = [
        "Algorithm",
        "Flash (Bytes)",
        "Stack HWM",
        "Heap Peak",
        "Cycles (32B Out)",
    ]
    rows_hash = []
    for d in HASH_DATA:
        rows_hash.append([
            d["name"],
            format_cell_latex(d["flash"], base_hash["flash"]),
            format_cell_latex(d["stack_hwm"], base_hash["stack_hwm"]),
            format_cell_latex(d["heap_peak"], base_hash["heap_peak"]),
            format_cell_latex(d["cycles"], base_hash["cycles"]),
        ])
    latex_blocks.append(
        build_latex_table(
            caption="HASH Algorithms Benchmark Performance.",
            label="tab:hash_benchmark",
            headers=headers_hash,
            rows=rows_hash,
            footnote="Comparisons expressed relative to SHA3-256.",
        )
    )

    # --- 7. KEM BENCHMARK TABLE ---
    base_kem = next(d for d in KEM_DATA if d["name"] == "X-Wing")
    headers_kem = [
        "Algorithm",
        "Flash (Bytes)",
        "Stack HWM",
        "Heap Peak",
        "KeyGeneration Cycles",
        "Encapsulation Cycles",
        "Decapsulation Cycles",
    ]
    rows_kem = []
    for d in KEM_DATA:
        rows_kem.append([
            d["name"],
            format_cell_latex(d["flash"], base_kem["flash"]),
            format_cell_latex(d["stack_hwm"], base_kem["stack_hwm"]),
            format_cell_latex(d["heap_peak"], base_kem["heap_peak"]),
            format_cell_latex(d["cycles_keygeneration"], base_kem["cycles_keygeneration"]),
            format_cell_latex(d["cycles_encapsulation"], base_kem["cycles_encapsulation"]),
            format_cell_latex(d["cycles_decapsulation"], base_kem["cycles_decapsulation"]),
        ])
    latex_blocks.append(
        build_latex_table(
            caption="KEM Framework and Primitive Benchmark Results.",
            label="tab:kem_benchmark",
            headers=headers_kem,
            rows=rows_kem,
            footnote="Comparisons expressed relative to X-Wing.",
        )
    )

    # --- 8. KEM x AEAD FLASH MATRIX TABLE ---
    headers_matrix = ["KEM"] + list(
        next(iter(KEM_AEAD_FLASH.values())).keys()
    )
    rows_matrix = []
    for kem, aeads in KEM_AEAD_FLASH.items():
        row = [kem] + [f"{aeads[aead]:,} B" for aead in headers_matrix[1:]]
        rows_matrix.append(row)
    latex_blocks.append(
        build_latex_table(
            caption="Flash memory consumption (Bytes) for combined KEM and AEAD implementations.",
            label="tab:kem_aead_flash_matrix",
            headers=headers_matrix,
            rows=rows_matrix,
            footnote="Flash values measured in Bytes for each combined deployment.",
        )
    )

    # Write all LaTeX tables into text file
    with open(output_filepath, "w", encoding="utf-8") as f:
        f.write("\n\n".join(latex_blocks))

    print(f"Saved LaTeX tables text file: {output_filepath}")


# =============================================================================
# 4. PLOTTING FUNCTIONS
# =============================================================================


def plot_static_size(data_list, family_name):
    """Plots Flash, Stack HWM, and Heap Peak (64B for AEAD) as a grouped vertical bar chart."""
    if not data_list:
        return

    names = [d["name"] for d in data_list]
    flash = [d["flash"] for d in data_list]
    stack = [d["stack_hwm"] for d in data_list]

    heap = [
        d["heap_peak"][1] if isinstance(d["heap_peak"], list) else d["heap_peak"]
        for d in data_list
    ]

    x = np.arange(len(names))
    width = 0.25

    fig, ax = plt.subplots(figsize=(10, 6))

    ax.bar(x - width, flash, width, label="Flash Size (Bytes)", color="#1f77b4")
    ax.bar(x, stack, width, label="Stack HWM (Bytes)", color="#ff7f0e")
    ax.bar(x + width, heap, width, label="Heap Peak (Bytes)", color="#2ca02c")

    ax.set_ylabel("Size in Bytes")
    ax.set_title(
        f"{family_name} Memory Footprint (Flash, Stack & Heap [64B])"
        if family_name == "AEAD"
        else f"{family_name} Memory Footprint (Flash, Stack & Heap)"
    )
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=35, ha="right")

    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.7)

    save_plot(f"{family_name}_Size_Memory_Footprint.png")


def plot_aead_heap_peak_sizes(data_list):
    """Plots AEAD Heap Peak usage as a line graph across all payload sizes."""
    if not data_list:
        return

    x = np.arange(len(AEAD_SIZES))
    fig, ax = plt.subplots(figsize=(8, 6))

    for d in data_list:
        ax.plot(x, d["heap_peak"], marker="o", label=d["name"])

    ax.set_xticks(x)
    ax.set_xticklabels([f"{s}B" for s in AEAD_SIZES])
    ax.set_xlabel("Payload Size (Bytes)")
    ax.set_ylabel("Heap Peak (Bytes)")
    ax.set_title("AEAD Heap Peak Usage Across Payload Sizes")
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.7)

    save_plot("AEAD_Size_Heap.png")


def plot_aead_speed_64b(data_list):
    """Plots AEAD Encrypt & Decrypt Cycles for 64B payload as a grouped bar chart."""
    if not data_list:
        return

    idx_64 = 1  # 64B payload index
    names = [d["name"] for d in data_list]
    enc_cycles = [d["cycles_enc"][idx_64] for d in data_list]
    dec_cycles = [d["cycles_dec"][idx_64] for d in data_list]

    x = np.arange(len(names))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(
        x - width / 2, enc_cycles, width, label="Encrypt Cycles", color="#1f77b4"
    )
    ax.bar(
        x + width / 2, dec_cycles, width, label="Decrypt Cycles", color="#ff7f0e"
    )

    ax.set_ylabel("Cycles")
    ax.set_title("AEAD Speed (64 Bytes Payload)")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=35, ha="right")
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.7)

    save_plot("AEAD_Speed_Cycles_64B.png")


def plot_aead_speed(data_list):
    """Plots AEAD Cycles for Encrypt and Decrypt across all payload sizes."""
    if not data_list:
        return

    x = np.arange(len(AEAD_SIZES))

    # Encrypt Plot
    fig, ax = plt.subplots(figsize=(8, 6))
    for d in data_list:
        ax.plot(x, d["cycles_enc"], marker="o", linewidth=2, label=d["name"])

    ax.set_xlabel("Payload Size (Bytes)")
    ax.set_ylabel("Cycles")
    ax.set_title("AEAD Speed: Encryption Cycles Across Payload Sizes")
    ax.set_xticks(x)
    ax.set_xticklabels([f"{s}B" for s in AEAD_SIZES])
    ax.legend()
    ax.grid(True, linestyle="--", alpha=0.7)
    save_plot("AEAD_Speed_Encrypt.png")

    # Decrypt Plot
    fig, ax = plt.subplots(figsize=(8, 6))
    for d in data_list:
        ax.plot(x, d["cycles_dec"], marker="s", linewidth=2, label=d["name"])

    ax.set_xlabel("Payload Size (Bytes)")
    ax.set_ylabel("Cycles")
    ax.set_title("AEAD Speed: Decryption Cycles Across Payload Sizes")
    ax.set_xticks(x)
    ax.set_xticklabels([f"{s}B" for s in AEAD_SIZES])
    ax.legend()
    ax.grid(True, linestyle="--", alpha=0.7)
    save_plot("AEAD_Speed_Decrypt.png")


def plot_hash_speed(data_list):
    """Plots HASH Cycles for outputting 32 bytes."""
    if not data_list:
        return

    names = [d["name"] for d in data_list]
    cycles = [d["cycles"] for d in data_list]

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.bar(names, cycles, color="#9467bd", width=0.5)

    ax.set_ylabel("Cycles")
    ax.set_title("HASH Speed (Outputting 32 Bytes)")
    ax.grid(axis="y", linestyle="--", alpha=0.7)
    save_plot("HASH_Speed_Cycles.png")


def plot_kem_speed(data_list):
    """Plots KEM Cycles as a grouped bar chart for KeyGeneration, Encapsulation, and Decapsulation."""
    if not data_list:
        return

    names = [d["name"] for d in data_list]
    keygeneration = [d["cycles_keygeneration"] for d in data_list]
    encapsulation = [d["cycles_encapsulation"] for d in data_list]
    decapsulation = [d["cycles_decapsulation"] for d in data_list]

    x = np.arange(len(names))
    width = 0.25

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(x - width, keygeneration, width, label="KeyGeneration", color="#1f77b4")
    ax.bar(x, encapsulation, width, label="Encapsulation", color="#ff7f0e")
    ax.bar(x + width, decapsulation, width, label="Decapsulation", color="#2ca02c")

    ax.set_ylabel("Cycles")
    ax.set_title("KEM Speed (KeyGeneration, Encapsulation, Decapsulationulation)")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=35, ha="right")
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.7)

    save_plot("KEM_Speed_Cycles.png")


# =============================================================================
# 5. MAIN EXECUTION
# =============================================================================


def main():
    print(
        "Generating Benchmark Graphs, Table Images, Heatmaps, and LaTeX"
        " Tables..."
    )

    # --- AEAD Plots ---
    plot_static_size(AEAD_DATA, "AEAD")
    plot_aead_speed_64b(AEAD_DATA)
    plot_aead_heap_peak_sizes(AEAD_DATA)
    plot_aead_speed(AEAD_DATA)

    # --- HASH Plots ---
    plot_static_size(HASH_DATA, "HASH")
    plot_hash_speed(HASH_DATA)

    # --- KEM Plots ---
    plot_static_size(KEM_DATA, "KEM")
    plot_kem_speed(KEM_DATA)

    # --- Standard Table Picture Generation ---
    generate_image_tables()

    # --- KEM x AEAD Color-Coded Heatmap Matrix Image ---
    plot_kem_aead_flash_table()

    # --- LaTeX Table Output in .txt file ---
    generate_latex_tables()

    print(f"\nAll outputs successfully saved in '{OUTPUT_DIR}'.")


if __name__ == "__main__":
    main()