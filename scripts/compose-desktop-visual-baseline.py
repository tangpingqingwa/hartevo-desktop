#!/usr/bin/env python3
"""Compose reproducible Hartevo prototype/desktop visual comparison artifacts."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont, ImageStat


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_ROOT = ROOT / "artifacts" / "visual" / "prototype-baseline"
REFERENCE_ROOT = ARTIFACT_ROOT / "references"
SURFACE_ROOT = ARTIFACT_ROOT / "surfaces"
COMPARISON_ROOT = ARTIFACT_ROOT / "comparisons"
RESPONSIVE_ROOT = ARTIFACT_ROOT / "responsive"

SURFACES = (
    "orchestrator",
    "mission-conversation",
    "mission-streaming",
    "mission-workpad",
    "mission-inspector",
    "mission-approval",
    "mission-outcome",
    "current",
    "missions",
    "channels",
    "relationships",
    "partners",
    "connections",
    "outcomes",
    "capability-evidence",
    "settings",
    "state-coverage",
)

COMPARABLE_SURFACES = (
    "orchestrator",
    "mission-conversation",
    "mission-streaming",
    "mission-workpad",
    "mission-approval",
    "mission-outcome",
    "channels",
    "relationships",
    "partners",
    "connections",
    "outcomes",
    "capability-evidence",
    "settings",
)


def font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = (
        Path("/System/Library/Fonts/PingFang.ttc"),
        Path("/System/Library/Fonts/SFNS.ttf"),
    )
    for candidate in candidates:
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size=size)
    return ImageFont.load_default()


def contain(image: Image.Image, width: int, height: int) -> Image.Image:
    result = Image.new("RGB", (width, height), "#f6f6f7")
    copy = image.convert("RGB")
    copy.thumbnail((width, height), Image.Resampling.LANCZOS)
    offset = ((width - copy.width) // 2, (height - copy.height) // 2)
    result.paste(copy, offset)
    return result


def captioned(image: Image.Image, label: str, width: int, height: int) -> Image.Image:
    header_height = 34
    panel = Image.new("RGB", (width, height + header_height), "#ffffff")
    panel.paste(contain(image, width, height), (0, header_height))
    draw = ImageDraw.Draw(panel)
    draw.text((12, 8), label, fill="#202124", font=font(13))
    draw.line((0, header_height - 1, width, header_height - 1), fill="#e6e6e8", width=1)
    return panel


def implementation_path(surface: str) -> Path:
    return SURFACE_ROOT / f"{surface}-macos-content.png"


def reference_path(surface: str, width: int, height: int) -> Path:
    candidates = (
        REFERENCE_ROOT / f"{surface}-prototype-{width}x{height}.png",
        REFERENCE_ROOT / f"{surface}-prototype-{width}x{height}.jpg",
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        f"missing same-viewport source reference for {surface}: "
        + ", ".join(str(candidate) for candidate in candidates)
    )


def content_viewport() -> tuple[int, int]:
    with Image.open(implementation_path("orchestrator")) as source:
        return source.size


def compose_surface_contact_sheet() -> None:
    tile_width, tile_height = 683, 435
    tiles: list[Image.Image] = []
    for surface in SURFACES:
        path = implementation_path(surface)
        with Image.open(path) as source:
            tiles.append(captioned(source, f"Dioxus Desktop · {surface}", tile_width, tile_height))

    rows = (len(tiles) + 1) // 2
    sheet = Image.new("RGB", (tile_width * 2, (tile_height + 34) * rows), "#ececee")
    for index, tile in enumerate(tiles):
        sheet.paste(tile, ((index % 2) * tile_width, (index // 2) * (tile_height + 34)))
    sheet.save(ARTIFACT_ROOT / "surface-contact-sheet.png", optimize=True)


def compose_comparisons() -> None:
    COMPARISON_ROOT.mkdir(parents=True, exist_ok=True)
    content_width, content_height = content_viewport()
    preview_width, preview_height = 683, 435
    comparison_rows: list[Image.Image] = []

    for surface in COMPARABLE_SURFACES:
        source_reference_path = reference_path(surface, content_width, content_height)
        surface_implementation_path = implementation_path(surface)
        with Image.open(source_reference_path) as reference, Image.open(
            surface_implementation_path
        ) as implementation:
            full_reference = captioned(
                reference, f"Source prototype · {surface}", content_width, content_height
            )
            full_implementation = captioned(
                implementation,
                f"Dioxus Desktop · {surface}",
                content_width,
                content_height,
            )
            pair = Image.new(
                "RGB", (content_width * 2, content_height + 34), "#ececee"
            )
            pair.paste(full_reference, (0, 0))
            pair.paste(full_implementation, (content_width, 0))
            pair.save(COMPARISON_ROOT / f"{surface}-side-by-side.png", optimize=True)

            row = Image.new("RGB", (1366, preview_height + 34), "#ececee")
            row.paste(captioned(reference, f"Source · {surface}", preview_width, preview_height), (0, 0))
            row.paste(
                captioned(implementation, f"Dioxus · {surface}", preview_width, preview_height),
                (preview_width, 0),
            )
            comparison_rows.append(row)

    contact = Image.new(
        "RGB", (1366, (preview_height + 34) * len(comparison_rows)), "#ececee"
    )
    for index, row in enumerate(comparison_rows):
        contact.paste(row, (0, index * (preview_height + 34)))
    contact.save(ARTIFACT_ROOT / "comparison-contact-sheet.png", optimize=True)


def compose_responsive_contact_sheet() -> None:
    cases = (
        ("baseline", "1366×900 requested · native clamp recorded"),
        ("compact", "1024×768 content · PASS"),
        ("zoom-200", "1024×768 content · 200% zoom · PASS"),
        ("wide", "1600×1000 requested · BLOCKED_ENV_SCREEN_BOUNDS"),
    )
    width, height = 604, 384
    sheet = Image.new("RGB", (width * 2, (height + 34) * 2), "#ececee")
    for index, (case, label) in enumerate(cases):
        path = RESPONSIVE_ROOT / f"{case}-window-native-sky.png"
        with Image.open(path) as source:
            tile = captioned(source, label, width, height)
        sheet.paste(tile, ((index % 2) * width, (index // 2) * (height + 34)))
    sheet.save(RESPONSIVE_ROOT / "responsive-contact-sheet.png", optimize=True)


def reject_blank_or_black_evidence() -> None:
    failures: list[str] = []
    candidates = sorted(
        path
        for path in ARTIFACT_ROOT.rglob("*")
        if path.suffix.lower() in {".png", ".jpg", ".jpeg"}
    )
    for path in candidates:
        with Image.open(path) as source:
            statistics = ImageStat.Stat(source.convert("RGB"))
        mean = sum(statistics.mean) / len(statistics.mean)
        contrast = sum(statistics.stddev) / len(statistics.stddev)
        if mean < 5 or contrast < 1:
            failures.append(f"{path.relative_to(ARTIFACT_ROOT)} (mean={mean:.2f}, contrast={contrast:.2f})")
    if failures:
        raise RuntimeError("blank/black visual evidence rejected: " + ", ".join(failures))


if __name__ == "__main__":
    compose_surface_contact_sheet()
    compose_comparisons()
    compose_responsive_contact_sheet()
    reject_blank_or_black_evidence()
    print(f"wrote visual baseline composites under {ARTIFACT_ROOT}")
