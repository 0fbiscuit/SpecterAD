"""Parser — dual-strategy JSON parsing with per-file threshold.

Strategy:
    - File < threshold (default 200MB): orjson.loads() — fastest bulk parse.
    - File >= threshold: ijson streaming — parse data.item one by one to avoid
      RAM exhaustion on large computers.json / containers.json.
"""

from __future__ import annotations

import logging
from io import BytesIO

import ijson
import orjson

from specterad.ingestor.exceptions import IngestionError

logger = logging.getLogger(__name__)

# Default threshold in bytes (200 MB)
DEFAULT_STREAM_THRESHOLD_BYTES: int = 200 * 1024 * 1024


def _parse_bulk(raw_bytes: bytes) -> tuple[str, list[dict]]:
    """Fast-path: parse entire JSON into memory with orjson.

    Returns:
        (meta_type, list_of_data_objects)
    """
    try:
        doc = orjson.loads(raw_bytes)
    except orjson.JSONDecodeError as exc:
        raise IngestionError(f"Invalid JSON: {exc}") from exc

    if not isinstance(doc, dict):
        raise IngestionError(
            f"Expected JSON object at root, got {type(doc).__name__}"
        )

    # Validate required fields
    meta = doc.get("meta")
    if meta is None:
        raise IngestionError("Missing 'meta' block in JSON")

    meta_type = meta.get("type")
    if not meta_type:
        raise IngestionError("Missing 'meta.type' field in JSON")

    data = doc.get("data")
    if data is None:
        raise IngestionError("Missing 'data' array in JSON")

    if not isinstance(data, list):
        raise IngestionError(
            f"Expected 'data' to be an array, got {type(data).__name__}"
        )

    expected_count = meta.get("count")
    actual_count = len(data)

    if expected_count is not None and expected_count != actual_count:
        logger.warning(
            "meta.count mismatch: expected %d, got %d (type=%s)",
            expected_count,
            actual_count,
            meta_type,
        )

    logger.debug(
        "Bulk parsed %d objects of type '%s'", actual_count, meta_type
    )
    return meta_type, data


def _parse_streaming(raw_bytes: bytes) -> tuple[str, list[dict]]:
    """Slow-path: streaming parse for large files with ijson.

    Reads ``data.item`` objects one by one via SAX-style events.
    Also extracts ``meta.type`` without loading the full document.

    Returns:
        (meta_type, list_of_data_objects)
    """
    stream = BytesIO(raw_bytes)

    # First pass: extract meta.type
    meta_type: str | None = None
    try:
        for prefix, event, value in ijson.parse(stream):
            if prefix == "meta.type" and event == "string":
                meta_type = value
                break
    except ijson.JSONError as exc:
        raise IngestionError(f"Invalid JSON (streaming): {exc}") from exc

    if not meta_type:
        raise IngestionError(
            "Could not find 'meta.type' via streaming parser"
        )

    # Second pass: extract data items
    stream.seek(0)
    objects: list[dict] = []
    try:
        for obj in ijson.items(stream, "data.item"):
            objects.append(obj)
    except ijson.JSONError as exc:
        raise IngestionError(
            f"Failed to stream 'data' array: {exc}"
        ) from exc

    logger.debug(
        "Stream parsed %d objects of type '%s'", len(objects), meta_type
    )
    return meta_type, objects


def parse_json_file(
    raw_bytes: bytes,
    file_size: int,
    stream_threshold_mb: int = 200,
) -> tuple[str, list[dict]]:
    """Parse a single SharpHound JSON file using the optimal strategy.

    Strategy selected **per-file** based on ``file_size``:
        - Below threshold → orjson bulk parse (fast).
        - At or above threshold → ijson streaming (memory-safe).

    Args:
        raw_bytes: Raw file content.
        file_size: Size of the file in bytes.
        stream_threshold_mb: Threshold in MB for switching to streaming.

    Returns:
        Tuple of (meta_type, list_of_raw_data_dicts).

    Raises:
        IngestionError: On parse failure or missing required fields.
    """
    threshold_bytes = stream_threshold_mb * 1024 * 1024

    if file_size >= threshold_bytes:
        logger.info(
            "File size %d MB >= threshold %d MB → streaming parser",
            file_size // (1024 * 1024),
            stream_threshold_mb,
        )
        return _parse_streaming(raw_bytes)
    else:
        logger.debug(
            "File size %d KB < threshold → bulk parser (orjson)",
            file_size // 1024,
        )
        return _parse_bulk(raw_bytes)
