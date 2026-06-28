"""
src/main.py
────────────
CLI entry point for the AI Cyber Security Suite data engineering pipeline.

Run the full pipeline:
    python -m src.main

Run individual stages:
    python -m src.main --inspect
    python -m src.main --clean
    python -m src.main --validate
    python -m src.main --merge
    python -m src.main --inspect --clean        (chain stages)

Pipeline order:
    inspect -> clean -> validate -> merge
"""

import io
import sys

# ── Force UTF-8 stdout/stderr on Windows (cp1252 can't encode box-drawing chars)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
else:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]

import argparse
import time

from colorama import Fore, Style, init as colorama_init

from src.utils.logger import logger

colorama_init(autoreset=True)


# ── Banner ─────────────────────────────────────────────────────────────────────

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║         🛡️  AI Cyber Security Suite — Data Pipeline        ║
║                    Milestone 1: Data Engineering           ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""


# ── Stage runners ──────────────────────────────────────────────────────────────

def run_inspect() -> None:
    from src.data.inspect import DatasetInspector
    logger.info("═" * 50)
    logger.info("STAGE: Inspect")
    logger.info("═" * 50)
    inspector = DatasetInspector()
    inspector.discover()
    inspector.inspect()


def run_clean() -> None:
    from src.data.clean import DataCleaner
    logger.info("═" * 50)
    logger.info("STAGE: Clean")
    logger.info("═" * 50)
    cleaner = DataCleaner()
    cleaner.clean_all()


def run_validate() -> None:
    from src.data.validate import DataValidator
    logger.info("═" * 50)
    logger.info("STAGE: Validate")
    logger.info("═" * 50)
    validator = DataValidator()
    validator.validate_all()


def run_merge() -> None:
    from src.data.merge import DataMerger
    logger.info("═" * 50)
    logger.info("STAGE: Merge")
    logger.info("═" * 50)
    merger = DataMerger()
    merger.merge()


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.main",
        description="AI Cyber Security Suite — Data Engineering Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m src.main                 # run full pipeline\n"
            "  python -m src.main --inspect       # inspect only\n"
            "  python -m src.main --clean         # clean only\n"
            "  python -m src.main --inspect --clean --validate --merge\n"
        ),
    )
    parser.add_argument("--inspect",  action="store_true", help="Run dataset inspection")
    parser.add_argument("--clean",    action="store_true", help="Run dataset cleaning")
    parser.add_argument("--validate", action="store_true", help="Run dataset validation")
    parser.add_argument("--merge",    action="store_true", help="Run dataset merging")
    return parser.parse_args()


def main() -> None:
    print(BANNER)
    args = parse_args()

    # If no flags are given, run the full pipeline
    run_all = not any([args.inspect, args.clean, args.validate, args.merge])

    stages: list[tuple[str, callable]] = []

    if run_all or args.inspect:
        stages.append(("Inspect", run_inspect))
    if run_all or args.clean:
        stages.append(("Clean", run_clean))
    if run_all or args.validate:
        stages.append(("Validate", run_validate))
    if run_all or args.merge:
        stages.append(("Merge", run_merge))

    start_total = time.perf_counter()

    for name, fn in stages:
        t0 = time.perf_counter()
        try:
            fn()
            elapsed = time.perf_counter() - t0
            logger.info("%s stage completed in %.2fs", name, elapsed)
        except Exception as exc:  # noqa: BLE001
            logger.error("%s stage failed: %s", name, exc)
            sys.exit(1)

    total = time.perf_counter() - start_total
    print(f"\n{Fore.GREEN}✓ Pipeline finished in {total:.2f}s{Style.RESET_ALL}\n")
    logger.info("Pipeline complete. Total time: %.2fs", total)


if __name__ == "__main__":
    main()
