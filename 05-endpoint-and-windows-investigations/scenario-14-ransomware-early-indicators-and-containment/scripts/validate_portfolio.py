#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "README.md",
    "dataset-decision-record.md",
    "evidence-inventory.md",
    "triage-note.md",
    "investigation-notes.md",
    "investigation-report.md",
    "recommended-actions.md",
    "containment-decision-record.md",
    "recovery-plan.md",
    "detection-engineering.md",
    "validation-checklist.md",
    "source-and-license-record.md",
    "github-publishing-guide.md",
    ".gitignore",
]

FORBIDDEN_SUFFIXES = {
    ".exe",
    ".dll",
    ".sys",
    ".evtx",
    ".etl",
    ".pcap",
    ".pcapng",
    ".zip",
    ".7z",
    ".rar",
    ".pyc",
}

ALLOWED_PLACEHOLDERS = {
    "evidence/raw/.gitkeep",
    "evidence/working/.gitkeep",
    "screenshots/.gitkeep",
}

errors: list[str] = []


def run_git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


# Check required public portfolio files.
for relative_path in REQUIRED_FILES:
    if not (ROOT / relative_path).is_file():
        errors.append(f"Missing required file: {relative_path}")


# Determine whether the Scenario directory is inside a Git repository.
repo_check = run_git("rev-parse", "--show-toplevel")
inside_git_repository = repo_check.returncode == 0


if inside_git_repository:
    repository_root = Path(repo_check.stdout.strip()).resolve()

    try:
        scenario_relative_path = (
            ROOT.resolve()
            .relative_to(repository_root)
            .as_posix()
        )
    except ValueError:
        errors.append(
            "Scenario directory is not under the detected Git repository root."
        )
        scenario_relative_path = ""

    publishable_files: list[tuple[Path, str]] = []

    if scenario_relative_path:
        listed = run_git(
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            scenario_relative_path,
        )

        if listed.returncode != 0:
            errors.append(
                f"git ls-files failed: {listed.stderr.strip()}"
            )
        else:
            for repository_relative_name in listed.stdout.splitlines():
                repository_relative_name = repository_relative_name.strip()

                if not repository_relative_name:
                    continue

                full_path = repository_root / repository_relative_name

                try:
                    scenario_relative_name = (
                        full_path
                        .relative_to(ROOT)
                        .as_posix()
                    )
                except ValueError:
                    continue

                publishable_files.append(
                    (full_path, scenario_relative_name)
                )

    # Review only files that Git considers tracked or publishable.
    for full_path, relative_name in publishable_files:
        if full_path.suffix.lower() in FORBIDDEN_SUFFIXES:
            errors.append(
                f"Forbidden publishable file type: {relative_name}"
            )

        if "__pycache__" in full_path.parts:
            errors.append(
                f"Publishable Python cache present: {relative_name}"
            )

        if (
            relative_name.startswith("evidence/raw/")
            and relative_name not in ALLOWED_PLACEHOLDERS
        ):
            errors.append(
                f"Raw evidence would be publishable: {relative_name}"
            )

        if (
            relative_name.startswith("evidence/working/")
            and relative_name not in ALLOWED_PLACEHOLDERS
        ):
            errors.append(
                f"Working evidence would be publishable: {relative_name}"
            )

        if (
            relative_name.startswith("screenshots/")
            and relative_name not in ALLOWED_PLACEHOLDERS
        ):
            errors.append(
                f"Unreviewed screenshot would be publishable: {relative_name}"
            )

    # Local raw and working evidence may exist, but every top-level item
    # other than .gitkeep must be ignored by Git.
    for directory_name in [
        "evidence/raw",
        "evidence/working",
    ]:
        directory = ROOT / directory_name

        if not directory.exists():
            continue

        for path in directory.iterdir():
            if path.name == ".gitkeep":
                continue

            ignore_result = run_git(
                "check-ignore",
                "-q",
                "--",
                str(path),
            )

            if ignore_result.returncode != 0:
                errors.append(
                    f"Local evidence is not ignored: "
                    f"{path.relative_to(ROOT)}"
                )

else:
    # Standalone ZIP/package mode: raw and working directories must contain
    # placeholders only.
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue

        relative_name = path.relative_to(ROOT).as_posix()

        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            errors.append(
                f"Forbidden file type: {relative_name}"
            )

        if "__pycache__" in path.parts:
            errors.append(
                f"Python cache present: {relative_name}"
            )

        if (
            relative_name.startswith("evidence/raw/")
            and relative_name not in ALLOWED_PLACEHOLDERS
        ):
            errors.append(
                f"Raw evidence is present in the public package: "
                f"{relative_name}"
            )

        if (
            relative_name.startswith("evidence/working/")
            and relative_name not in ALLOWED_PLACEHOLDERS
        ):
            errors.append(
                f"Working evidence is present in the public package: "
                f"{relative_name}"
            )


if errors:
    print("VALIDATION FAILED")

    for error in errors:
        print(f"- {error}")

    sys.exit(1)


mode = (
    "Git-aware repository mode"
    if inside_git_repository
    else "Standalone package mode"
)

print("VALIDATION PASSED")
print(f"Mode: {mode}")
print(f"Root: {ROOT}")

if inside_git_repository:
    print(
        "Ignored local raw and working evidence was checked "
        "but not treated as publishable content."
    )
