#!/usr/bin/env python3
"""Scan all Azure Repos in selected projects for new secrets."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import ssl
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


def safe_path_component(value: str) -> str:
    """Keep the Azure name recognizable without allowing it to escape the work tree."""
    component = re.sub(r"[\\/]", "_", value).strip()
    return component if component not in {"", ".", ".."} else "_"


def api_get(url: str, pat: str, proxy: str, ssl_verify: bool) -> tuple[Any, str | None]:
    token = base64.b64encode(f":{pat}".encode()).decode()
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Basic {token}", "Accept": "application/json"},
    )
    handlers: list[Any] = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    if not ssl_verify:
        handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=60) as response:
            continuation = response.headers.get("x-ms-continuationtoken")
            return json.load(response), continuation
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")
        raise RuntimeError(f"Azure DevOps API returned HTTP {error.code}: {detail}") from error


def list_repositories(
    org_url: str, project: str, pat: str, proxy: str, ssl_verify: bool
) -> list[dict[str, Any]]:
    project_path = urllib.parse.quote(project, safe="")
    base_url = f"{org_url.rstrip('/')}/{project_path}/_apis/git/repositories"
    repositories: list[dict[str, Any]] = []
    continuation: str | None = None
    page = 0
    print(f"Listing repositories for project {project} from {base_url}", flush=True)
    while True:
        page += 1
        query = {"api-version": API_VERSION, "$top": "1000"}
        if continuation:
            query["continuationToken"] = continuation
        payload, continuation = api_get(
            f"{base_url}?{urllib.parse.urlencode(query)}", pat, proxy, ssl_verify
        )
        page_repositories = payload.get("value", [])
        repositories.extend(page_repositories)
        print(
            f"Listed page {page} for project {project}: "
            f"{len(page_repositories)} repo(s), {len(repositories)} total",
            flush=True,
        )
        if not continuation:
            print(
                f"Finished listing project {project}: {len(repositories)} repo(s)",
                flush=True,
            )
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


def clone_repository(
    repo: dict[str, Any],
    destination: Path,
    pat: str,
    org_url: str,
    proxy: str,
    ssl_verify: bool,
) -> None:
    env = os.environ.copy()
    env["AZURE_DEVOPS_PAT"] = pat
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = str(Path(__file__).with_name("git_askpass.sh").resolve())
    command = ["git"]
    git_url = org_url.rstrip("/")
    if proxy:
        command.extend(["-c", f"http.{git_url}.proxy={proxy}"])
    command.extend(["-c", f"http.{git_url}.sslVerify={'true' if ssl_verify else 'false'}"])
    command.extend(["clone", "--quiet", "--depth", "1", "--no-tags"])
    default_branch = repo.get("defaultBranch")
    if default_branch:
        command.extend(["--branch", default_branch.removeprefix("refs/heads/")])
    command.extend([repo["remoteUrl"], str(destination)])
    result = run(command, cwd=destination.parent, env=env)
    if result.returncode != 0:
        raise RuntimeError(result.stdout.strip() or "git clone failed")


def scan_repository(repo_path: Path, num_cores: int) -> tuple[str, int, str]:
    baseline = repo_path / ".secrets.baseline"
    if not baseline.is_file():
        return "missing_baseline", 0, "Repository root has no .secrets.baseline"

    try:
        before = baseline_entries(baseline)
    except (json.JSONDecodeError, OSError) as error:
        return "scan_error", 0, f"Invalid .secrets.baseline: {error}"

    # This updates the working-copy baseline; the repository itself is never pushed.
    result = run(
        [
            "detect-secrets",
            "scan",
            "--baseline",
            ".secrets.baseline",
            "--num-cores",
            str(num_cores),
        ],
        cwd=repo_path,
    )
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
    proxy = os.environ.get("AZURE_DEVOPS_PROXY", "").strip()
    ssl_verify = os.environ.get("AZURE_DEVOPS_SSL_VERIFY", "true").strip().lower() not in {
        "0", "false", "no", "off"
    }
    num_cores_value = os.environ.get("DETECT_SECRETS_NUM_CORES", "2").strip()
    report_dir = Path(os.environ.get("REPORT_DIR", "secret-scan-report")).resolve()
    if not pat or pat == "$(AZURE_DEVOPS_PAT)":
        print("##vso[task.logissue type=error]AZURE_DEVOPS_PAT is required and must be configured as a secret pipeline variable")
        return 2
    if not org_url or not projects:
        print("##vso[task.logissue type=error]AZURE_DEVOPS_ORG_URL and AZURE_DEVOPS_PROJECTS are required")
        return 2
    try:
        num_cores = int(num_cores_value)
        if num_cores < 1:
            raise ValueError
    except ValueError:
        print("##vso[task.logissue type=error]DETECT_SECRETS_NUM_CORES must be a positive integer")
        return 2

    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="azure-repo-secret-scan-") as temp:
        work_root = Path(temp)
        print(f"Work root: {work_root}", flush=True)
        print(f"detect-secrets worker processes: {num_cores}", flush=True)
        for project in projects:
            print(f"##[group]Project: {project}")
            project_root = work_root / safe_path_component(project)
            project_root.mkdir(parents=True, exist_ok=True)
            try:
                repositories = list_repositories(org_url, project, pat, proxy, ssl_verify)
            except Exception as error:
                print(f"##[error]{error}")
                results.append({"project": project, "repository": "*", "status": "scan_error", "newFindings": 0, "detail": str(error)})
                print("##[endgroup]")
                continue

            for repo in repositories:
                name = repo["name"]
                qualified_name = f"{project}/{name}"
                if name in allowlist or qualified_name in allowlist:
                    status, count, detail = "skipped", 0, "Repository is allowlisted"
                elif repo.get("isDisabled"):
                    status, count, detail = "skipped", 0, "Repository is disabled"
                elif not repo.get("defaultBranch"):
                    status, count, detail = "skipped", 0, "Repository is empty or has no default branch"
                else:
                    repo_path = project_root / safe_path_component(name)
                    try:
                        print(f"Cloning {qualified_name} to {repo_path}", flush=True)
                        clone_repository(repo, repo_path, pat, org_url, proxy, ssl_verify)
                        print(
                            f"Scanning {qualified_name} in {repo_path} with {num_cores} worker(s)",
                            flush=True,
                        )
                        status, count, detail = scan_repository(repo_path, num_cores)
                    except Exception as error:
                        status, count, detail = "scan_error", 0, str(error)
                    finally:
                        if repo_path.exists():
                            print(f"Cleaning up {qualified_name} from {repo_path}", flush=True)
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
