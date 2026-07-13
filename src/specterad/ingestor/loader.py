"""Loader — discover and read SharpHound ZIP archives or JSON directories.

Supports two input modes:
1. A .zip file: extracted in-memory via zipfile.ZipFile + BytesIO
2. A directory: scanned for *.json files on disk

Each discovered JSON file is yielded as a (filename, bytes, file_size) tuple
for downstream parsing.
"""

from __future__ import annotations

import logging
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Iterator

from specterad.ingestor.exceptions import IngestionError

logger = logging.getLogger(__name__)


def _discover_json_in_zip(
    zip_path: Path,
) -> Iterator[tuple[str, bytes, int]]:
    """Extract JSON files from a SharpHound ZIP into memory.

    Yields:
        (filename, raw_bytes, file_size_bytes) for each .json entry.

    Raises:
        IngestionError: If the ZIP is invalid or contains no JSON files.
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            json_entries = [
                info
                for info in zf.infolist()
                if info.filename.lower().endswith(".json") and not info.is_dir()
            ]

            if not json_entries:
                raise IngestionError(
                    f"No JSON files found inside ZIP: {zip_path}"
                )

            logger.info(
                "Found %d JSON file(s) in %s", len(json_entries), zip_path.name
            )

            for info in json_entries:
                raw = zf.read(info.filename)
                logger.debug(
                    "  %s — %d bytes", info.filename, len(raw)
                )
                yield info.filename, raw, len(raw)

    except zipfile.BadZipFile as exc:
        raise IngestionError(f"Invalid ZIP file: {zip_path}") from exc


def _discover_json_in_dir(
    dir_path: Path,
) -> Iterator[tuple[str, bytes, int]]:
    """Read JSON files from a directory on disk.

    Yields:
        (filename, raw_bytes, file_size_bytes) for each .json file.

    Raises:
        IngestionError: If no JSON files are found.
    """
    json_files = sorted(dir_path.glob("*.json"))

    if not json_files:
        raise IngestionError(f"No JSON files found in directory: {dir_path}")

    logger.info("Found %d JSON file(s) in %s", len(json_files), dir_path)

    for fpath in json_files:
        file_size = fpath.stat().st_size
        raw = fpath.read_bytes()
        logger.debug("  %s — %d bytes", fpath.name, file_size)
        yield fpath.name, raw, file_size


def discover_json_files(
    source: str | Path,
) -> Iterator[tuple[str, bytes, int]]:
    """Auto-detect source type and yield JSON file contents.

    Args:
        source: Path to a .zip file or a directory containing JSON files.

    Yields:
        (filename, raw_bytes, file_size_bytes) tuples.

    Raises:
        IngestionError: If source is invalid or contains no JSON.
    """
    source = Path(source)

    if not source.exists():
        raise IngestionError(f"Source path does not exist: {source}")

    if source.is_file() and source.suffix.lower() == ".zip":
        yield from _discover_json_in_zip(source)
    elif source.is_dir():
        yield from _discover_json_in_dir(source)
    else:
        raise IngestionError(
            f"Source must be a .zip file or directory, got: {source}"
        )


def load_sharphound_data(
    source: str | Path,
    stream_threshold_mb: int = 200,
) -> dict[str, list[dict]]:
    """High-level loader: source → dict of {meta_type: [raw_objects]}.

    Orchestrates the full pipeline: discover → parse → group by type.

    Args:
        source: Path to ZIP or directory.
        stream_threshold_mb: Per-file size threshold in MB for streaming parser.

    Returns:
        Dict mapping SharpHound meta.type (e.g. "users") to list of raw
        object dicts from the ``data`` array.

    Raises:
        IngestionError: On any loading or parsing failure.
    """
    from specterad.ingestor.parser import parse_json_file

    result: dict[str, list[dict]] = {}

    for filename, raw_bytes, file_size in discover_json_files(source):
        try:
            meta_type, objects = parse_json_file(
                raw_bytes, file_size, stream_threshold_mb
            )
        except Exception as exc:
            raise IngestionError(
                f"Failed to parse {filename}: {exc}"
            ) from exc

        if meta_type in result:
            # Merge objects if multiple files of the same type exist
            result[meta_type].extend(objects)
            logger.info(
                "Merged %d objects into type '%s' from %s",
                len(objects),
                meta_type,
                filename,
            )
        else:
            result[meta_type] = objects
            logger.info(
                "Loaded %d objects of type '%s' from %s",
                len(objects),
                meta_type,
                filename,
            )

    return result
