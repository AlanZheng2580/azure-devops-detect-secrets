#!/usr/bin/env python3
"""Scan all Azure Repos in selected projects for new secrets."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


API_VERSION = "7.1"


def split_setting(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[,\n]", value) if item.strip()]


def api_get(url: str, pat: str) -> tuple[Any, str | None]:
    token = base64.b64encode(f":{pat}".encode()).decode()
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Basic {token}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            continuation = response.headers.get("x-ms-continuationtoken")
            return json.load(response), continuation
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")
        raise RuntimeError(f"Azure DevOps API returned HTTP {error.code}: {detail}") from error


def list_repositories(org_url: str, project: str, pat: str) -> list[dict[str, Any]]:
    project_path = urllib.parse.quote(project, safe="")
    base_url = f"{org_url.rstrip('/')}/{project_path}/_apis/git/repositories"
    repositories: list[dict[str, Any]] = []
    continuation: str | None = None
    while True:
        query = {"api-version": API_VERSION, "$top": "1000"}
        if continuation:
            query["continuationToken"] = continuation
        payload, continuation = api_get(f"{base_url}?{urllib.parse.urlencode(query)}", pat)
        repositories.extend(payload.get("value", []))
        if not continuation:
            return repositories


def baseline_entries(path: Path) -> set[tuple[str, str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries: set[tuple[str, str, str]] = set()
    for filename, findings in data.get("results", {}).items():
        for finding in findings:
            entries.add(
                (
                    filename,
                    str(finding.get("type", "")),
                    str(finding.get("hashed_secret", "")),
                )
            )
    return entries


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def clone_repository(repo: dict[str, Any], destination: Path, pat: str) -> None:
    env = os.environ.copy()
    env["AZURE_DEVOPS_PAT"] = pat
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = str(Path(__file__).with_name("git_askpass.sh").resolve())
    command = ["git", "clone", "--quiet", "--depth", "1", "--no-tags"]
    default_branch = repo.get("defaultBranch")
    if default_branch:
        command.extend(["--branch", default_branch.removeprefix("refs/heads/")])
    command.extend([repo["remoteUrl"], str(destination)])
    result = run(command, cwd=destination.parent, env=env)
    if result.returncode != 0:
        raise RuntimeError(result.stdout.strip() or "git clone failed")


def scan_repository(repo_path: Path) -> tuple[str, int, str]:
    baseline = repo_path / ".secrets.baseline"
    if not baseline.is_file():
        return "missing_baseline", 0, "Repository root has no .secrets.baseline"

    try:
        before = baseline_entries(baseline)
    except (json.JSONDecodeError, OSError) as error:
        return "scan_error", 0, f"Invalid .secrets.baseline: {error}"

    # This updates the working-copy baseline; the repository itself is never pushed.
    result = run(["detect-secrets", "scan", "--baseline", ".secrets.baseline"], cwd=repo_path)
    if result.returncode != 0:
        return "scan_error", 0, result.stdout.strip()

    try:
        after = baseline_entries(baseline)
    except (json.JSONDecodeError, OSError) as error:
        return "scan_error", 0, f"Could not read scan result: {error}"

    new_count = len(after - before)
    if new_count:
        return "secrets_detected", new_count, f"Detected {new_count} finding(s) not in baseline"
    return "clean", 0, "No findings outside the existing baseline"


def write_reports(report_dir: Path, results: list[dict[str, Any]]) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).isoformat()
    summary = {
        "generatedAt": generated_at,
        "counts": {status: sum(row["status"] == status for row in results) for status in (
            "clean", "secrets_detected", "missing_baseline", "scan_error", "skipped"
        )},
        "repositories": results,
    }
    (report_dir / "report.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    lines = [
        "# Azure Repos secret scan",
        "",
        f"Generated: {generated_at}",
        "",
        "| Project | Repository | Status | New findings | Detail |",
        "|---|---|---:|---:|---|",
    ]
    for row in results:
        detail = str(row["detail"]).replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {row['project']} | {row['repository']} | {row['status']} | "
            f"{row['newFindings']} | {detail} |"
        )
    (report_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    pat = os.environ.get("AZURE_DEVOPS_PAT", "")
    org_url = os.environ.get("AZURE_DEVOPS_ORG_URL", "")
    projects = split_setting(os.environ.get("AZURE_DEVOPS_PROJECTS", ""))
    allowlist = set(split_setting(os.environ.get("REPO_ALLOWLIST", "")))
    report_dir = Path(os.environ.get("REPORT_DIR", "secret-scan-report")).resolve()
    if not pat or not org_url or not projects:
        print("AZURE_DEVOPS_PAT, AZURE_DEVOPS_ORG_URL, and AZURE_DEVOPS_PROJECTS are required", file=sys.stderr)
        return 2

    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="azure-repo-secret-scan-") as temp:
        work_root = Path(temp)
        for project in projects:
            print(f"##[group]Project: {project}")
            try:
                repositories = list_repositories(org_url, project, pat)
            except Exception as error:
                print(f"##[error]{error}")
                results.append({"project": project, "repository": "*", "status": "scan_error", "newFindings": 0, "detail": str(error)})
                print("##[endgroup]")
                continue

            for index, repo in enumerate(repositories):
                name = repo["name"]
                qualified_name = f"{project}/{name}"
                if name in allowlist or qualified_name in allowlist:
                    status, count, detail = "skipped", 0, "Repository is allowlisted"
                elif repo.get("isDisabled"):
                    status, count, detail = "skipped", 0, "Repository is disabled"
                elif not repo.get("defaultBranch"):
                    status, count, detail = "skipped", 0, "Repository is empty or has no default branch"
                else:
                    repo_path = work_root / f"repo-{len(results)}-{index}"
                    try:
                        clone_repository(repo, repo_path, pat)
                        status, count, detail = scan_repository(repo_path)
                    except Exception as error:
                        status, count, detail = "scan_error", 0, str(error)
                    finally:
                        if repo_path.exists():
                            shutil.rmtree(repo_path)

                print(f"{qualified_name}: {status} - {detail}")
                results.append({"project": project, "repository": name, "status": status, "newFindings": count, "detail": detail})
            print("##[endgroup]")

    write_reports(report_dir, results)
    failures = [row for row in results if row["status"] in {"missing_baseline", "secrets_detected", "scan_error"}]
    print(f"Scanned {len(results)} repositories; {len(failures)} require attention.")
    if failures:
        print("##[error]Secret scan policy failed. Download the secret-scan-report artifact for details.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

