"""
backend/api/routers/download.py
───────────────────────────────────
Endpoint for downloading the pre-built Chrome Extension (.zip)
GET /v1/download/extension
"""

import io
import os
import zipfile
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

router = APIRouter()

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXTENSION_DIST = PROJECT_ROOT / "extension" / "dist"


@router.get("/download/extension", tags=["Download"])
async def download_extension():
    """
    Builds an in-memory zip archive of extension/dist and streams it as ai-cyber-security-extension.zip.
    """
    if not EXTENSION_DIST.exists() or not (EXTENSION_DIST / "manifest.json").exists():
        raise HTTPException(
            status_code=404,
            detail="Extension bundle not found. Please run 'npm run build' inside the extension directory first.",
        )

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for root, _, files in os.walk(EXTENSION_DIST):
            for file in files:
                file_path = Path(root) / file
                archive_name = file_path.relative_to(EXTENSION_DIST)
                zip_file.write(file_path, archive_name)

    zip_buffer.seek(0)
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="ai-cyber-security-extension.zip"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )
