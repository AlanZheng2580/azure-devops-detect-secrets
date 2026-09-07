# Azure Repos nightly detect-secrets scan

This pipeline enumerates every repository in selected Azure DevOps projects, skips an optional allowlist, checks for a root-level `.secrets.baseline`, and runs `detect-secrets scan --baseline .secrets.baseline`. It fails when a baseline is missing, a new finding appears, an API/clone/scan fails, or the baseline is invalid.

Repositories are cloned temporarily using a `<project>/<repository>` directory layout. For example, repositories returned from `https://dev.azure.com/tsmcit/EPS/` are placed under `<temporary-directory>/EPS/<repository>`. The temporary tree is removed as each scan completes.

## Azure DevOps setup

1. Create a PAT with read-only **Code** access to all projects that will be scanned. If the projects are in another organization, also set `AZURE_DEVOPS_ORG_URL` to that organization's URL instead of using `$(System.CollectionUri)`.
2. In the pipeline UI, create a secret variable named `AZURE_DEVOPS_PAT`. Do not put the PAT in YAML or a variable group as plain text.
3. Edit these variables in `azure-pipelines.yml`, or override them in the pipeline UI/variable group:
   - `AZURE_DEVOPS_PROJECTS`: comma/newline separated project names, for example `EPS,HCM,Dig Work`.
   - `REPO_ALLOWLIST`: comma/newline separated entries. `repo-a` skips that repo name in every project; `EPS/repo-a` only skips it in EPS.
   - `AZURE_DEVOPS_PROXY`: proxy used by both the REST API and `git clone`; leave empty for a direct connection.
   - `AZURE_DEVOPS_SSL_VERIFY`: controls TLS certificate verification for both REST and Git. Prefer `true` with the internal CA installed. The supplied TSMC proxy example uses `false`.
   - `DETECT_SECRETS_NUM_CORES`: maximum multiprocessing workers used by each scan; defaults to `2`.

The worker limit is passed as a global option before the subcommand: `detect-secrets -c 2 scan --baseline .secrets.baseline`.
4. Ensure the pipeline's default branch matches the `main` branch in the schedule. Azure DevOps only evaluates scheduled triggers from the YAML version on the configured default branch.

The sample cron runs every day at 21:00 Asia/Taipei (`13:00 UTC`). Azure Pipelines cron schedules always use UTC.

The job stops immediately with a configuration error when the secret `AZURE_DEVOPS_PAT` variable is missing. Git receives the PAT through `scripts/git_askpass.sh`; this avoids embedding the credential in the clone URL or command-line arguments where it could be logged. The pipeline explicitly sets the helper's executable permission before scanning.

Proxy and TLS options are passed only to the scanner's HTTP client and Git process. The pipeline does not change the agent-wide `git config --system` settings.

## Run locally

Run the following from the repository root. The silent prompt keeps the PAT out of shell history and terminal output:

```bash
python3 -m venv /tmp/azure-repo-secret-scan-venv
. /tmp/azure-repo-secret-scan-venv/bin/activate
python -m pip install "detect-secrets==1.5.0"

read -rsp "Azure DevOps PAT: " queue_pat
printf '\n'
export AZURE_DEVOPS_PAT="$queue_pat"
unset queue_pat

export AZURE_DEVOPS_ORG_URL="https://dev.azure.com/tsmcit/"
export AZURE_DEVOPS_PROJECTS="EPS,HCM,Dig Work"
export REPO_ALLOWLIST="repo-to-skip,EPS/project-specific-repo"
export AZURE_DEVOPS_PROXY="http://saas-proxy.psp.svc.cluster.local:30080"
export AZURE_DEVOPS_SSL_VERIFY="false"
export DETECT_SECRETS_NUM_CORES="2"
export REPORT_DIR="$PWD/secret-scan-report"

chmod 700 scripts/git_askpass.sh
python scripts/scan_azure_repos.py

unset AZURE_DEVOPS_PAT
deactivate
```

For a direct connection, use `export AZURE_DEVOPS_PROXY=""`. If the internal CA is trusted locally, use `export AZURE_DEVOPS_SSL_VERIFY="true"`. Reports are written to `secret-scan-report/report.md` and `secret-scan-report/report.json`; exit code `1` means at least one repository requires attention.

## Output and status

The `secret-scan-report` pipeline artifact contains both `report.md` and machine-readable `report.json`. A repository is assigned one of these statuses:

- `clean`: no new finding compared with its committed baseline.
- `secrets_detected`: one or more findings were added by the scan.
- `missing_baseline`: the repository root has no `.secrets.baseline`.
- `scan_error`: API, clone, baseline parsing, or scanner failure.
- `skipped`: allowlisted, disabled, or empty repository.

The scan never commits or pushes the baseline updated in its temporary working copy.
