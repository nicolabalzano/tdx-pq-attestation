#!/usr/bin/env python3
"""
Generate thesis-ready PNG charts from attestation_benchmarks.json.

The script reads the aggregated benchmark JSON produced by:
    tdx_tests/results/attestation_benchmarks.json

It generates the four main direct-path charts plus auxiliary charts:
  1. Quote size comparison
  2. Direct-path latency by stage
  3. End-to-end latency comparison
  4. End-to-end stage share (100% stacked)
  5. Direct-path latency without collateral fetch
  6. End-to-end latency without collateral fetch
  7. End-to-end stage share without collateral fetch

No third-party Python dependencies are required.
The final raster images are generated through ImageMagick `convert`.
"""

from __future__ import annotations

import argparse
import json
import math
import shutil
import subprocess
from pathlib import Path
from typing import Iterable
from xml.sax.saxutils import escape


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_JSON = REPO_ROOT / "tdx_tests" / "results" / "attestation_benchmarks.json"
DEFAULT_OUT_DIR = REPO_ROOT / "docs" / "figures" / "generated"

ALGORITHM_ORDER = ["ecdsa_p256", "mldsa_44", "mldsa_65", "mldsa_87"]
ALGORITHM_LABELS = {
    "ecdsa_p256": "ECDSA",
    "mldsa_44": "ML-DSA-44",
    "mldsa_65": "ML-DSA-65",
    "mldsa_87": "ML-DSA-87",
}
ALGORITHM_COLORS = {
    "ecdsa_p256": "#4C78A8",
    "mldsa_44": "#F58518",
    "mldsa_65": "#54A24B",
    "mldsa_87": "#E45756",
}

STAGE_ORDER = ["quote_generation", "collateral_fetch", "verification"]
STAGE_LABELS = {
    "quote_generation": "Quote generation",
    "collateral_fetch": "Collateral fetch",
    "verification": "Verification",
    "report_generation": "Report generation",
}
STAGE_COLORS = {
    "report_generation": "#9D9D9D",
    "quote_generation": "#4C78A8",
    "collateral_fetch": "#E45756",
    "verification": "#54A24B",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate PNG charts from attestation benchmark JSON."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_JSON,
        help=f"Path to aggregated benchmark JSON (default: {DEFAULT_JSON})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUT_DIR,
        help=f"Directory where PNG files are written (default: {DEFAULT_OUT_DIR})",
    )
    return parser.parse_args()


def load_direct_scenarios(json_path: Path) -> dict[str, dict]:
    with json_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    direct = {}
    for scenario in payload["scenarios"]:
        meta = scenario["scenario"]
        if meta["path_mode"] != "direct":
            continue
        direct[meta["algorithm"]] = scenario

    missing = [alg for alg in ALGORITHM_ORDER if alg not in direct]
    if missing:
        raise SystemExit(
            f"Missing direct-path scenarios in {json_path}: {', '.join(missing)}"
        )
    return direct


def nice_step(max_value: float, tick_count: int = 5) -> float:
    if max_value <= 0:
        return 1.0
    raw = max_value / tick_count
    exponent = math.floor(math.log10(raw))
    fraction = raw / (10 ** exponent)
    if fraction <= 1:
        nice_fraction = 1
    elif fraction <= 2:
        nice_fraction = 2
    elif fraction <= 5:
        nice_fraction = 5
    else:
        nice_fraction = 10
    return nice_fraction * (10 ** exponent)


def nice_ceiling(max_value: float, tick_count: int = 5) -> float:
    step = nice_step(max_value, tick_count)
    return math.ceil(max_value / step) * step


def fmt_bytes(value: float) -> str:
    return f"{int(round(value)):,}".replace(",", " ")


def fmt_ms(value: float) -> str:
    if value >= 1000:
        return f"{value:.0f}"
    if value >= 100:
        return f"{value:.1f}"
    if value >= 10:
        return f"{value:.2f}"
    return f"{value:.3f}"


def fmt_percent(value: float) -> str:
    return f"{value:.0f}%"


def fmt_delta_percent(previous: float, current: float) -> str:
    if previous == 0:
        return "n/a"
    delta = ((current - previous) / previous) * 100.0
    sign = "+" if delta >= 0 else ""
    if abs(delta) >= 100:
        return f"{sign}{delta:.0f}%"
    if abs(delta) >= 10:
        return f"{sign}{delta:.1f}%"
    return f"{sign}{delta:.2f}%"


class SvgChart:
    def __init__(self, width: int = 1100, height: int = 700):
        self.width = width
        self.height = height
        self.elements: list[str] = []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def line(self, x1, y1, x2, y2, stroke="#333", stroke_width=1, dash="") -> None:
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(
            f'<line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" '
            f'stroke="{stroke}" stroke-width="{stroke_width}"{dash_attr} />'
        )

    def path(self, d: str, stroke="#333", stroke_width=1, fill="none", dash="") -> None:
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(
            f'<path d="{d}" fill="{fill}" stroke="{stroke}" '
            f'stroke-width="{stroke_width}"{dash_attr} />'
        )

    def rect(self, x, y, w, h, fill, stroke="none", stroke_width=0, rx=0) -> None:
        self.add(
            f'<rect x="{x:.2f}" y="{y:.2f}" width="{w:.2f}" height="{h:.2f}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{stroke_width}" rx="{rx}" />'
        )

    def text(
        self,
        x,
        y,
        content,
        size=18,
        weight="normal",
        anchor="start",
        fill="#111",
        rotate=None,
    ) -> None:
        transform = ""
        if rotate is not None:
            transform = f' transform="rotate({rotate:.2f} {x:.2f} {y:.2f})"'
        self.add(
            f'<text x="{x:.2f}" y="{y:.2f}" font-family="DejaVu Sans, Arial, sans-serif" '
            f'font-size="{size}" font-weight="{weight}" text-anchor="{anchor}" '
            f'fill="{fill}"{transform}>{escape(str(content))}</text>'
        )

    def render_svg(self) -> str:
        svg = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.width}" height="{self.height}" '
            f'viewBox="0 0 {self.width} {self.height}">',
            '<rect width="100%" height="100%" fill="#ffffff" />',
            *self.elements,
            "</svg>",
        ]
        return "\n".join(svg)

    def save_png(self, path: Path, density: int = 220) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_svg = path.with_suffix(".tmp.svg")
        temp_svg.write_text(self.render_svg(), encoding="utf-8")
        convert = shutil.which("convert")
        if convert is None:
            raise SystemExit("ImageMagick 'convert' not found in PATH")
        try:
            subprocess.run(
                [
                    convert,
                    "-background",
                    "white",
                    "-density",
                    str(density),
                    str(temp_svg),
                    str(path),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            raise SystemExit(
                f"Failed to convert {temp_svg} to PNG:\n{exc.stderr}"
            ) from exc
        finally:
            temp_svg.unlink(missing_ok=True)


def draw_legend(chart: SvgChart, items: Iterable[tuple[str, str]], x: float, y: float) -> None:
    offset = 0.0
    for label, color in items:
        chart.rect(x + offset, y - 12, 18, 18, fill=color, stroke="#222", stroke_width=0.6)
        chart.text(x + offset + 26, y + 2, label, size=16)
        offset += 26 + len(label) * 8.5 + 24


def draw_pairwise_delta_connectors(
    chart: SvgChart,
    centers: list[float],
    top_y_positions: list[float],
    values: list[float],
    floor_y: float,
    stroke: str = "#2F2F2F",
) -> None:
    for idx in range(len(values) - 1):
        x1 = centers[idx]
        x2 = centers[idx + 1]
        y1 = top_y_positions[idx]
        y2 = top_y_positions[idx + 1]
        mid_x = (x1 + x2) / 2
        path_d = (
            f"M {x1:.2f} {y1:.2f} "
            f"L {mid_x:.2f} {y1:.2f} "
            f"L {mid_x:.2f} {y2:.2f} "
            f"L {x2:.2f} {y2:.2f}"
        )
        chart.path(path_d, stroke=stroke, stroke_width=1.6, dash="6 5")
        label_y = min(y1, y2) - 8
        label_y = max(floor_y, label_y)
        chart.text(
            (x1 + x2) / 2,
            label_y,
            fmt_delta_percent(values[idx], values[idx + 1]),
            size=13,
            weight="bold",
            anchor="middle",
            fill=stroke,
        )


def bar_chart(
    path: Path,
    labels: list[str],
    values: list[float],
    colors: list[str],
    value_formatter,
    axis_formatter,
    y_axis_label: str,
    show_delta_connectors: bool = True,
) -> None:
    chart = SvgChart()
    left, right = 110, 60
    top, bottom = (78 if show_delta_connectors else 40), 110
    plot_w = chart.width - left - right
    plot_h = chart.height - top - bottom

    ymax = nice_ceiling(max(values) * (1.24 if show_delta_connectors else 1.08), 5)
    step = nice_step(ymax, 5)

    chart.line(left, top + plot_h, left + plot_w, top + plot_h, stroke="#222", stroke_width=1.5)
    chart.line(left, top, left, top + plot_h, stroke="#222", stroke_width=1.5)
    chart.text(32, top + plot_h / 2, y_axis_label, size=16, rotate=-90, anchor="middle", fill="#444")

    tick = 0.0
    while tick <= ymax + 1e-9:
        y = top + plot_h - (tick / ymax) * plot_h
        chart.line(left, y, left + plot_w, y, stroke="#D9D9D9", stroke_width=1)
        chart.text(left - 12, y + 5, axis_formatter(tick), size=14, anchor="end", fill="#555")
        tick += step

    slot_w = plot_w / len(values)
    bar_w = min(110, slot_w * 0.58)
    centers = []
    top_y_positions = []
    for idx, (label, value, color) in enumerate(zip(labels, values, colors)):
        cx = left + slot_w * (idx + 0.5)
        x = cx - bar_w / 2
        h = (value / ymax) * plot_h
        y = top + plot_h - h
        centers.append(cx)
        top_y_positions.append(y)
        chart.rect(x, y, bar_w, h, fill=color, stroke="#333", stroke_width=0.8, rx=3)
        chart.text(cx, y - 10, value_formatter(value), size=15, anchor="middle", fill="#222")
        chart.text(cx, top + plot_h + 28, label, size=16, anchor="middle")

    if show_delta_connectors:
        draw_pairwise_delta_connectors(
            chart,
            centers=centers,
            top_y_positions=top_y_positions,
            values=values,
            floor_y=18,
        )

    chart.save_png(path)


def grouped_bar_chart(
    path: Path,
    categories: list[str],
    series_names: list[str],
    values_by_series: list[list[float]],
    series_colors: list[str],
    value_formatter,
    axis_formatter,
    y_axis_label: str,
) -> None:
    chart = SvgChart()
    draw_legend(chart, list(zip(series_names, series_colors)), 150, 44)

    left, right = 110, 60
    top, bottom = 85, 110
    plot_w = chart.width - left - right
    plot_h = chart.height - top - bottom

    flat_values = [value for row in values_by_series for value in row]
    ymax = nice_ceiling(max(flat_values) * 1.08, 6)
    step = nice_step(ymax, 6)

    chart.line(left, top + plot_h, left + plot_w, top + plot_h, stroke="#222", stroke_width=1.5)
    chart.line(left, top, left, top + plot_h, stroke="#222", stroke_width=1.5)
    chart.text(32, top + plot_h / 2, y_axis_label, size=16, rotate=-90, anchor="middle", fill="#444")

    tick = 0.0
    while tick <= ymax + 1e-9:
        y = top + plot_h - (tick / ymax) * plot_h
        chart.line(left, y, left + plot_w, y, stroke="#D9D9D9", stroke_width=1)
        chart.text(left - 12, y + 5, axis_formatter(tick), size=14, anchor="end", fill="#555")
        tick += step

    group_w = plot_w / len(categories)
    inner_w = group_w * 0.78
    bar_w = inner_w / len(series_names) * 0.78
    gap = (inner_w - bar_w * len(series_names)) / max(len(series_names) - 1, 1)
    for category_idx, category in enumerate(categories):
        group_left = left + group_w * category_idx + (group_w - inner_w) / 2
        for series_idx, series in enumerate(series_names):
            value = values_by_series[series_idx][category_idx]
            x = group_left + series_idx * (bar_w + gap)
            h = (value / ymax) * plot_h
            y = top + plot_h - h
            chart.rect(x, y, bar_w, h, fill=series_colors[series_idx], stroke="#333", stroke_width=0.6, rx=2)
            chart.text(x + bar_w / 2, y - 8, value_formatter(value), size=12, anchor="middle", fill="#222")
        chart.text(left + group_w * (category_idx + 0.5), top + plot_h + 28, category, size=16, anchor="middle")

    chart.save_png(path)


def percent_stacked_chart(
    path: Path,
    categories: list[str],
    shares_by_stage: dict[str, list[float]],
    stage_order: list[str],
    stage_colors: dict[str, str],
    secondary_labels_by_stage: dict[str, list[str]] | None = None,
    connector_values: list[float] | None = None,
) -> None:
    chart = SvgChart()
    draw_legend(
        chart,
        [(STAGE_LABELS[stage], stage_colors[stage]) for stage in stage_order],
        120,
        44,
    )

    left, right = 110, 60
    top, bottom = (120 if connector_values is not None else 85), 110
    plot_w = chart.width - left - right
    plot_h = chart.height - top - bottom

    chart.line(left, top + plot_h, left + plot_w, top + plot_h, stroke="#222", stroke_width=1.5)
    chart.line(left, top, left, top + plot_h, stroke="#222", stroke_width=1.5)
    chart.text(32, top + plot_h / 2, "Share of end-to-end latency [%]", size=16, rotate=-90, anchor="middle", fill="#444")

    for pct in range(0, 101, 20):
        y = top + plot_h - (pct / 100.0) * plot_h
        chart.line(left, y, left + plot_w, y, stroke="#D9D9D9", stroke_width=1)
        chart.text(left - 12, y + 5, f"{pct}", size=14, anchor="end", fill="#555")

    slot_w = plot_w / len(categories)
    bar_w = min(120, slot_w * 0.58)
    centers = []
    top_y_positions = []
    for idx, category in enumerate(categories):
        cx = left + slot_w * (idx + 0.5)
        x = cx - bar_w / 2
        centers.append(cx)
        top_y_positions.append(top)
        accum = 0.0
        for stage in stage_order:
            share = shares_by_stage[stage][idx]
            h = share * plot_h
            y = top + plot_h - accum * plot_h - h
            chart.rect(x, y, bar_w, h, fill=stage_colors[stage], stroke="#fff", stroke_width=1.0)
            if share >= 0.06:
                fill = "#111" if stage != "collateral_fetch" else "#fff"
                secondary = None
                if secondary_labels_by_stage is not None:
                    secondary = secondary_labels_by_stage.get(stage, [None] * len(categories))[idx]
                if secondary and share >= 0.10:
                    chart.text(
                        cx,
                        y + h / 2 - 3,
                        fmt_percent(share * 100),
                        size=13,
                        anchor="middle",
                        fill=fill,
                    )
                    chart.text(
                        cx,
                        y + h / 2 + 13,
                        secondary,
                        size=11,
                        anchor="middle",
                        fill=fill,
                    )
                else:
                    chart.text(
                        cx,
                        y + h / 2 + 5,
                        fmt_percent(share * 100),
                        size=13,
                        anchor="middle",
                        fill=fill,
                    )
            accum += share
        chart.rect(x, top, bar_w, plot_h, fill="none", stroke="#333", stroke_width=0.8)
        chart.text(cx, top + plot_h + 28, category, size=16, anchor="middle")

    if connector_values is not None:
        draw_pairwise_delta_connectors(
            chart,
            centers=centers,
            top_y_positions=top_y_positions,
            values=connector_values,
            floor_y=64,
        )

    chart.save_png(path)


def build_plot_data(direct_scenarios: dict[str, dict]) -> dict:
    labels = [ALGORITHM_LABELS[alg] for alg in ALGORITHM_ORDER]
    quote_sizes = [
        direct_scenarios[alg]["dimensions"]["quote_size_bytes"]["mean"] for alg in ALGORITHM_ORDER
    ]
    end_to_end = [
        direct_scenarios[alg]["latency_nanoseconds"]["end_to_end"]["mean"] / 1e6
        for alg in ALGORITHM_ORDER
    ]
    stage_latencies = {
        stage: [
            direct_scenarios[alg]["latency_nanoseconds"][stage]["mean"] / 1e6
            for alg in ALGORITHM_ORDER
        ]
        for stage in STAGE_ORDER
    }
    end_to_end_wo_collateral = []
    for alg in ALGORITHM_ORDER:
        lat = direct_scenarios[alg]["latency_nanoseconds"]
        adjusted = (
            lat["end_to_end"]["mean"]
            - lat["collateral_fetch"]["mean"]
        ) / 1e6
        end_to_end_wo_collateral.append(adjusted)
    share_order = ["report_generation", "quote_generation", "collateral_fetch", "verification"]
    stage_shares = {
        stage: [
            direct_scenarios[alg]["stage_share_of_end_to_end"][stage]
            for alg in ALGORITHM_ORDER
        ]
        for stage in share_order
    }
    share_order_wo_collateral = ["report_generation", "quote_generation", "verification"]
    stage_shares_wo_collateral = {stage: [] for stage in share_order_wo_collateral}
    stage_ms_labels_wo_collateral = {stage: [] for stage in share_order_wo_collateral}
    for alg in ALGORITHM_ORDER:
        shares = direct_scenarios[alg]["stage_share_of_end_to_end"]
        subtotal = sum(shares[stage] for stage in share_order_wo_collateral)
        for stage in share_order_wo_collateral:
            stage_shares_wo_collateral[stage].append(
                (shares[stage] / subtotal) if subtotal > 0 else 0.0
            )
            ms = direct_scenarios[alg]["latency_nanoseconds"][stage]["mean"] / 1e6
            stage_ms_labels_wo_collateral[stage].append(f"{fmt_ms(ms)} ms")
    return {
        "labels": labels,
        "quote_sizes": quote_sizes,
        "end_to_end_ms": end_to_end,
        "end_to_end_wo_collateral_ms": end_to_end_wo_collateral,
        "stage_latencies_ms": stage_latencies,
        "stage_shares": stage_shares,
        "share_order": share_order,
        "stage_shares_wo_collateral": stage_shares_wo_collateral,
        "share_order_wo_collateral": share_order_wo_collateral,
        "stage_ms_labels_wo_collateral": stage_ms_labels_wo_collateral,
    }


def main() -> None:
    args = parse_args()
    direct = load_direct_scenarios(args.input)
    plot_data = build_plot_data(direct)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    quote_path = args.output_dir / "quote_size_comparison.png"
    latency_stage_path = args.output_dir / "direct_path_latency_by_stage.png"
    latency_crypto_only_path = args.output_dir / "direct_path_latency_without_collateral.png"
    end_to_end_path = args.output_dir / "end_to_end_latency_comparison.png"
    share_path = args.output_dir / "end_to_end_stage_share.png"
    end_to_end_wo_collateral_path = args.output_dir / "end_to_end_latency_without_collateral.png"
    share_wo_collateral_path = args.output_dir / "end_to_end_stage_share_without_collateral.png"

    labels = plot_data["labels"]
    colors = [ALGORITHM_COLORS[alg] for alg in ALGORITHM_ORDER]

    bar_chart(
        quote_path,
        labels=labels,
        values=plot_data["quote_sizes"],
        colors=colors,
        value_formatter=fmt_bytes,
        axis_formatter=lambda v: fmt_bytes(v) if v else "0",
        y_axis_label="Quote size [bytes]",
    )

    grouped_bar_chart(
        latency_stage_path,
        categories=labels,
        series_names=[STAGE_LABELS[stage] for stage in STAGE_ORDER],
        values_by_series=[plot_data["stage_latencies_ms"][stage] for stage in STAGE_ORDER],
        series_colors=[STAGE_COLORS[stage] for stage in STAGE_ORDER],
        value_formatter=fmt_ms,
        axis_formatter=lambda v: fmt_ms(v) if v else "0",
        y_axis_label="Latency [ms]",
    )

    grouped_bar_chart(
        latency_crypto_only_path,
        categories=labels,
        series_names=[STAGE_LABELS[stage] for stage in ["quote_generation", "verification"]],
        values_by_series=[
            plot_data["stage_latencies_ms"]["quote_generation"],
            plot_data["stage_latencies_ms"]["verification"],
        ],
        series_colors=[
            STAGE_COLORS["quote_generation"],
            STAGE_COLORS["verification"],
        ],
        value_formatter=fmt_ms,
        axis_formatter=lambda v: fmt_ms(v) if v else "0",
        y_axis_label="Latency [ms]",
    )

    bar_chart(
        end_to_end_path,
        labels=labels,
        values=plot_data["end_to_end_ms"],
        colors=colors,
        value_formatter=fmt_ms,
        axis_formatter=lambda v: fmt_ms(v) if v else "0",
        y_axis_label="End-to-end latency [ms]",
    )

    bar_chart(
        end_to_end_wo_collateral_path,
        labels=labels,
        values=plot_data["end_to_end_wo_collateral_ms"],
        colors=colors,
        value_formatter=fmt_ms,
        axis_formatter=lambda v: fmt_ms(v) if v else "0",
        y_axis_label="Adjusted end-to-end latency [ms]",
    )

    percent_stacked_chart(
        share_path,
        categories=labels,
        shares_by_stage=plot_data["stage_shares"],
        stage_order=plot_data["share_order"],
        stage_colors=STAGE_COLORS,
        connector_values=plot_data["end_to_end_ms"],
    )

    percent_stacked_chart(
        share_wo_collateral_path,
        categories=labels,
        shares_by_stage=plot_data["stage_shares_wo_collateral"],
        stage_order=plot_data["share_order_wo_collateral"],
        stage_colors=STAGE_COLORS,
        secondary_labels_by_stage=plot_data["stage_ms_labels_wo_collateral"],
        connector_values=plot_data["end_to_end_wo_collateral_ms"],
    )

    manifest = {
        "input_json": str(args.input),
        "output_dir": str(args.output_dir),
        "plots": [
            str(quote_path),
            str(latency_stage_path),
            str(latency_crypto_only_path),
            str(end_to_end_path),
            str(share_path),
            str(end_to_end_wo_collateral_path),
            str(share_wo_collateral_path),
        ],
    }
    (args.output_dir / "plot_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    for output in manifest["plots"]:
        print(output)


if __name__ == "__main__":
    main()
