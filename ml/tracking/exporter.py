"""
ml/tracking/exporter.py
───────────────────────
Model and Feature Exporter — Finalises the pipeline.

Exports the final models, feature schema, and a consolidated
training report in HTML.

Usage
-----
    python -m ml.tracking.exporter
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

from src.config import REPORT_DIR, SELECTED_FEATURES
from src.utils.logger import logger


def generate_training_report():
    """Generates a simple HTML report combining metrics and plots."""
    logger.info("=" * 55)
    logger.info("Training Report Exporter")
    logger.info("=" * 55)
    
    html_path = REPORT_DIR / "training_report.html"
    
    # Check what images we have
    images = list(REPORT_DIR.glob("*.png"))
    image_tags = ""
    for img in sorted(images):
        # We can just link them relative to the report dir
        image_tags += f'''
        <div class="card">
            <h3>{img.stem.replace("_", " ").title()}</h3>
            <img src="{img.name}" alt="{img.stem}" style="max-width: 100%; height: auto;">
        </div>
        '''
        
    # Read feature selection schema
    schema_details = ""
    if SELECTED_FEATURES.exists():
        data = json.loads(SELECTED_FEATURES.read_text())
        schema_details = f"<p>Selected Features: {data.get('n_features', 0)}</p>"
        schema_details += f"<p>Dropped Features: {data.get('n_dropped', 0)}</p>"
        
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Phishing Detection - Training Report</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; padding: 20px; background-color: #f5f7fa; color: #333; }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }}
            .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); gap: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Model Training Report</h1>
            <div class="card">
                <h2>Execution Details</h2>
                <p>Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                {schema_details}
            </div>
            
            <h2>Artifacts</h2>
            <div class="grid">
                {image_tags}
            </div>
        </div>
    </body>
    </html>
    """
    
    html_path.write_text(html_content, encoding="utf-8")
    logger.info("Training report generated -> %s", html_path)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    generate_training_report()

if __name__ == "__main__":
    main()
