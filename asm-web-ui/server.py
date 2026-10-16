from __future__ import annotations

import asyncio
import csv
import ipaddress
import json
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import requests
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import database
from surfacedrift.advanced_runner import run_advanced_assessment

APP_DIR = Path(__file__).resolve().parent
_project_root_setting = os.getenv("ASM_PROJECT_ROOT")
if _project_root_setting:
    _project_root_path = Path(_project_root_setting)
    PROJECT_ROOT = (_project_root_path if _project_root_path.is_absolute() else APP_DIR / _project_root_path).resolve()
else:
    PROJECT_ROOT = APP_DIR.parent.resolve()

STATIC_DIR = APP_DIR / "static"
ARTIFACTS_DIR = Path(os.getenv("ASM_ARTIFACTS_DIR", str(APP_DIR / "artifacts"))).resolve()
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
RUNS_DIR = Path(os.getenv("ASM_RUNS_DIR", str(PROJECT_ROOT / "demo_run"))).resolve()
RUNS_DIR.mkdir(parents=True, exist_ok=True)
MAX_CONCURRENT_SCANS = max(1, int(os.getenv("ASM_MAX_CONCURRENT_SCANS", "1")))
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")

app = FastAPI(
    title="SurfaceDrift",
    description="Enterprise External Attack Surface Management & Continuous Threat Exposure Management",
    version="1.0.0",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()


# Models
class StartScanRequest(BaseModel):
    target: str = Field(min_length=3, max_length=300)
    authorized: bool
    mode: str = Field(default="passive", pattern="^(passive|active)$")


class ContinueSurfaceDriftRequest(BaseModel):
    categories: list[str] = Field(
        default_factory=lambda: [
            "http_probe",
            "takeover",
            "cloud_audit",
            "waf_bypass",
            "epss_kev",
            "email_sec",
            "js_secrets",
            "shadow_api",
            "eol_audit",
            "blh_audit",
            "waf_history",
            "waf_mapping",
            "config_probe",
            "tls_posture",
            "breach_intel",
            "typosquatting",
            "remediation",
        ]
    )


class GoogleAuthRequest(BaseModel):
    credential: Optional[str] = None
    demo: Optional[bool] = False
    email: Optional[str] = None
    name: Optional[str] = None
    picture: Optional[str] = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_current_user(
    asm_user_id: Optional[str] = Cookie(None),
    x_user_id: Optional[str] = Header(None)
) -> Optional[dict[str, Any]]:
    uid = asm_user_id or x_user_id
    if uid:
        return database.get_user_by_id(uid)
    return None


def normalize_target(raw: str) -> tuple[str, str]:
    value = raw.strip()
    if not value:
        raise ValueError("Enter a domain or public IP address.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid domain, public IP, or http(s) URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not accepted.")
    host = parsed.hostname.rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local", ".internal", ".test")):
        raise ValueError("Private or local hostnames cannot be scanned from this interface.")
    try:
        addr = ipaddress.ip_address(host)
        if isinstance(addr, ipaddress.IPv6Address):
            raise ValueError("The current ASM command-line version supports domains and public IPv4 addresses only.")
        if not addr.is_global:
            raise ValueError("Private, reserved, and local IP addresses are not allowed.")
    except ValueError as e:
        if "not allowed" in str(e) or "current ASM" in str(e):
            raise
        if len(host) > 253 or "." not in host:
            raise ValueError("Enter a fully qualified domain name, such as example.com.")
        labels = host.split(".")
        if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
            raise ValueError("The domain name contains invalid characters.")
        if len(labels[-1]) < 2:
            raise ValueError("The domain's final label is too short.")

    try:
        resolved = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ips = {item[4][0] for item in resolved}
        for ip in ips:
            parsed_ip = ipaddress.ip_address(ip)
            if not parsed_ip.is_global:
                raise ValueError("This host resolves to a private, reserved, or local IP address and cannot be scanned.")
    except socket.gaierror:
        pass
    return host, parsed.geturl()


def choose_wordlists() -> tuple[Path | None, Path | None]:
    wordlist_candidates = [
        PROJECT_ROOT / "resources" / "top100_sublist.txt",
        PROJECT_ROOT / "resources" / "top1000_sublist.txt",
        PROJECT_ROOT / "resources" / "bitquark_top100k_sublist.txt",
    ]
    subwordlist_candidates = [
        PROJECT_ROOT / "resources" / "top100_sublist.txt",
        PROJECT_ROOT / "resources" / "top1000_sublist.txt",
        PROJECT_ROOT / "resources" / "bitquark_top100k_sublist.txt",
    ]
    wordlist = next((p for p in wordlist_candidates if p.is_file()), None)
    subwordlist = next((p for p in subwordlist_candidates if p.is_file()), None)
    return wordlist, subwordlist


def preflight() -> dict[str, Any]:
    wordlist, subwordlist = choose_wordlists()
    runner = PROJECT_ROOT / "asm.py"
    modules = PROJECT_ROOT / "modules"
    ready = runner.is_file() and modules.is_dir() and wordlist is not None and subwordlist is not None
    return {
        "ready": ready,
        "python": sys.executable,
        "project_root": str(PROJECT_ROOT),
        "runner_exists": runner.is_file(),
        "modules_exist": modules.is_dir(),
        "wordlist": str(wordlist) if wordlist else None,
        "subwordlist": str(subwordlist) if subwordlist else None,
        "keylist_exists": (PROJECT_ROOT / "keylist.asm").is_file(),
    }


def parse_results(output_root: Path, target: str, duration: float, mode: str = "passive") -> dict[str, Any]:
    target_dirs = [p for p in output_root.iterdir() if p.is_dir()]
    result_dir = max(target_dirs, key=lambda p: p.stat().st_mtime) if target_dirs else output_root

    def read_clean_lines(filename: str) -> list[str]:
        p = result_dir / filename
        if not p.is_file():
            return []
        try:
            return [line.strip() for line in p.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
        except OSError:
            return []

    subdomains = read_clean_lines("subdomains.txt")
    dns_records = read_clean_lines("dns_records.txt")
    emails = read_clean_lines("emails.txt")
    guessed_emails = read_clean_lines("guessed_emails.txt")
    buckets = read_clean_lines("s3buckets.txt")
    creds = read_clean_lines("creds.txt")
    hashes = read_clean_lines("hashes.txt")
    usernames = read_clean_lines("usernames.txt")

    spoof_lines = read_clean_lines("email_spoof_checks.txt")
    spf_status = "Not detected"
    dmarc_status = "Not detected"
    for line in spoof_lines:
        lower = line.lower()
        if "spf" in lower:
            spf_status = line
        elif "dmarc" in lower:
            dmarc_status = line

    ip_records: list[dict[str, Any]] = []
    ports_and_vulns: list[dict[str, Any]] = []
    ports_count = 0
    vulns_count = 0
    ip_csv = result_dir / "target_ips.csv"
    if ip_csv.is_file():
        try:
            with ip_csv.open("r", newline="", encoding="utf-8", errors="replace") as f:
                for row in csv.DictReader(f):
                    ip = row.get("IP Address", "").strip()
                    if not ip:
                        continue
                    ports_str = row.get("Port/Protocol", "").strip()
                    asn = row.get("ASN", "").strip()
                    asn_desc = row.get("ASN Description", "").strip()
                    vulns_str = row.get("Vulnerabities", row.get("Vulnerabilities", "")).strip()
                    loc = row.get("Location", "").strip()

                    ports_list = [x.strip() for x in ports_str.split(",") if x.strip()] if ports_str else []
                    vulns_list = [x.strip() for x in vulns_str.split(",") if x.strip()] if vulns_str else []
                    ports_count += len(ports_list)
                    vulns_count += len(vulns_list)

                    item = {
                        "ip": ip,
                        "ports": ports_list,
                        "ports_raw": ports_str,
                        "asn": asn,
                        "asn_description": asn_desc,
                        "vulnerabilities": vulns_list,
                        "vulnerabilities_raw": vulns_str,
                        "location": loc,
                    }
                    ip_records.append(item)
                    if ports_list or vulns_list:
                        ports_and_vulns.append(item)
        except (OSError, csv.Error):
            pass

    employees: list[dict[str, str]] = []
    employee_csv = result_dir / "employees.csv"
    if employee_csv.is_file():
        try:
            with employee_csv.open("r", newline="", encoding="utf-8", errors="replace") as f:
                for row in csv.DictReader(f):
                    email = row.get("Email Address", "").strip()
                    full_name = row.get("Full Name", "").strip()
                    first_name = row.get("First Name", "").strip()
                    last_name = row.get("Last Name", "").strip()
                    linkedin = row.get("LinkedIn Profile URL", "").strip()
                    if email or full_name:
                        employees.append({
                            "email": email,
                            "full_name": full_name,
                            "first_name": first_name,
                            "last_name": last_name,
                            "linkedin_url": linkedin,
                        })
        except (OSError, csv.Error):
            pass

    artifact_details: list[dict[str, Any]] = []
    for p in sorted(result_dir.rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(result_dir))
            size = p.stat().st_size
            preview = ""
            lines_in_file = 0
            if size < 500_000:
                try:
                    text_content = p.read_text(encoding="utf-8", errors="replace")
                    file_lines = text_content.splitlines()
                    lines_in_file = len(file_lines)
                    preview = "\n".join(file_lines[:100])
                    if len(file_lines) > 100:
                        preview += f"\n... [Truncated: showing first 100 of {lines_in_file} lines]"
                except Exception:
                    preview = "[Binary or unreadable file]"
            artifact_details.append({
                "name": p.name,
                "relative_path": rel,
                "size_bytes": size,
                "line_count": lines_in_file,
                "preview": preview,
            })

    report: dict[str, Any] = {
        "target": target,
        "mode": mode,
        "duration_seconds": round(duration, 2),
        "completed_at": utc_now(),
        "result_folder": result_dir.name,
        "counts": {
            "subdomains": len(subdomains),
            "dns_records": len(dns_records),
            "ips": len(ip_records),
            "ports": ports_count,
            "emails": len(emails),
            "guessed_emails": len(guessed_emails),
            "employees": len(employees),
            "buckets": len(buckets),
            "vulns": vulns_count,
            "creds": len(creds),
            "hashes": len(hashes),
            "usernames": len(usernames),
            "artifacts": len(artifact_details),
        },
        "sections": {
            "subdomains": subdomains,
            "dns_records": dns_records,
            "ip_records": ip_records,
            "ports_and_vulns": ports_and_vulns,
            "emails": emails,
            "guessed_emails": guessed_emails,
            "employees": employees,
            "buckets": buckets,
            "email_security": {
                "spf": spf_status,
                "dmarc": dmarc_status,
                "raw_lines": spoof_lines,
            },
            "credentials": {
                "creds": creds,
                "hashes": hashes,
                "usernames": usernames,
            },
            "artifacts": artifact_details,
        },
        "files": [a["name"] for a in artifact_details],
        "notes": [
            "Counts reflect verified artifacts produced by this reconnaissance run.",
            f"Assessment executed in {'Active / Deep Recon' if mode == 'active' else 'Passive / Stealth OSINT'} mode.",
        ],
    }

    try:
        (output_root / "ASM_Scan_Summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    except Exception:
        pass

    count_lines = [
        "SURFACEDRIFT SCAN SUMMARY",
        "=========================",
        f"Target: {target}",
        f"Mode: {mode.title()}",
        f"Status: completed",
        f"Duration: {duration:.2f} seconds",
        f"Completed (UTC): {report['completed_at']}",
        "",
        "DISCOVERED ASSETS",
    ]
    for label, amount in report["counts"].items():
        count_lines.append(f"{label.replace('_', ' ').title()}: {amount}")
    count_lines += ["", "Included artifacts:"] + [f"- {name}" for name in report["files"]]
    count_lines += ["", *report["notes"]]
    try:
        (output_root / "ASM_Scan_Summary.txt").write_text("\n".join(count_lines) + "\n", encoding="utf-8")
    except Exception:
        pass
    return report


def zip_results(output_root: Path, scan_id: str) -> Path:
    zip_path = ARTIFACTS_DIR / f"asm-report-{scan_id}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for item in output_root.rglob("*"):
            if item.is_file():
                archive.write(item, arcname=str(Path(output_root.name) / item.relative_to(output_root)))
    return zip_path


def update_job(scan_id: str, **changes: Any) -> None:
    with JOBS_LOCK:
        if scan_id in JOBS:
            JOBS[scan_id].update(changes)
            JOBS[scan_id]["updated_at"] = utc_now()


def set_stage(scan_id: str, progress: int, stage: str, detail: str | None = None) -> None:
    update_job(scan_id, progress=progress, stage=stage, detail=detail or stage)


def stage_from_line(line: str, current: int) -> tuple[int, str, str]:
    low = line.lower()
    if "certificate transparency" in low or "crt.sh" in low:
        return max(current, 22), "Certificate Transparency", "Harvesting subdomains from Certificate Transparency (crt.sh) logs"
    if "hackertarget" in low:
        return max(current, 30), "HackerTarget OSINT", "Enumerating hosts and DNS mappings via HackerTarget"
    if "virustotal" in low:
        return max(current, 38), "VirusTotal Intelligence", "Querying VirusTotal API for passive subdomains and sibling records"
    if "urlscan" in low:
        return max(current, 45), "URLScan Web Intel", "Analyzing crawl data and website topology on URLScan.io"
    if "dnsdumpster" in low:
        return max(current, 52), "DNSDumpster Topology", "Querying DNSDumpster records and network topology"
    if "aws s3" in low or "s3 buckets" in low or "grayhat" in low:
        return max(current, 60), "Cloud Storage Audit", "Searching GrayHatWarfare for exposed AWS S3 buckets"
    if "dns brute" in low or "subbrute" in low:
        return max(current, 68), "Active DNS Brute-Forcing", "Probing wordlist subdomains against DNS resolvers"
    if "spf" in low or "dmarc" in low or "mx records" in low or "dns records" in low:
        return max(current, 75), "Mail Security & DNS", "Auditing SPF, DMARC spoofing configuration and MX records"
    if "shodan" in low or "censys" in low or "port_scan" in low or "ip address:" in low:
        return max(current, 82), "Port & Service Telemetry", "Querying Shodan and Censys APIs for exposed ports and services"
    if "hunter" in low or "email" in low or "employee" in low:
        return max(current, 86), "People & Email Signals", "Harvesting employee profiles and corporate email patterns"
    if "results saved" in low or "saved to subfolder" in low or "building report" in low:
        return max(current, 92), "Finalizing Intelligence", "Aggregating artifacts and preparing report bundle"
    if "target [" in low or "added." in low:
        return max(current, 15), "Target Added", line.strip()

    # Generic detail extractor for clean terminal lines
    clean_line = line.strip()
    if any(clean_line.startswith(p) for p in ("[-]", "[+]", "[*]", "[i]", "||")):
        return current, "Reconnaissance in progress", clean_line
    return current, "Running reconnaissance", clean_line[:120] if clean_line else "Querying intelligence sources..."


def run_scan(scan_id: str, target: str, mode: str = "passive", user_id: Optional[str] = None) -> None:
    start = time.monotonic()
    output_root = RUNS_DIR / f"{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    output_root.mkdir(parents=True, exist_ok=False)
    update_job(
        scan_id,
        status="running",
        progress=5,
        stage="Preparing scan",
        detail=f"Initializing {mode.title()} reconnaissance engine...",
        output_root=str(output_root),
        started_at=utc_now()
    )

    try:
        runner_script = PROJECT_ROOT / "asm.py"
        wordlist, subwordlist = choose_wordlists()
        if not runner_script.is_file() or not wordlist or not subwordlist:
            update_job(scan_id, status="failed", stage="Missing files", error="Scanner files or wordlists could not be found.")
            database.record_scan_completion(scan_id, "failed", 0)
            return

        key_file = PROJECT_ROOT / "keylist.asm"
        if not key_file.is_file():
            try:
                key_file.write_text("virustotal = \"\"\nhunterio = \"\"\nshodan = \"\"\ngrayhatwarfare = \"\"\ncensys_id = \"\"\ncensys_secret = \"\"\n", encoding="utf-8")
            except OSError:
                pass

        cmd = [
            sys.executable, "-u", str(runner_script),
            "-t", target,
            "-w", str(wordlist.relative_to(PROJECT_ROOT)),
            "-sw", str(subwordlist.relative_to(PROJECT_ROOT)),
            "-o", str(output_root),
        ]
        if mode == "passive":
            cmd.append("-sth")
        else:
            cmd.append("-e")  # Recursive expansion in active mode

        set_stage(scan_id, 10, "Starting ASM Engine", f"Launched AttackSurfaceMapper in {mode.title()} mode")
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=env,
            )
        except OSError as exc:
            update_job(scan_id, status="failed", stage="Launch failed", error=str(exc))
            database.record_scan_completion(scan_id, "failed", 0)
            return

        log_lines: list[str] = []
        current_progress = 10
        current_stage = "Running reconnaissance"
        current_detail = "Querying intelligence sources..."
        timeout_seconds = int(os.getenv("ASM_SCAN_TIMEOUT_SECONDS", "900"))
        assert proc.stdout is not None
        output_queue: queue.Queue[str | None] = queue.Queue()

        def read_output() -> None:
            try:
                for output_line in proc.stdout:
                    output_queue.put(output_line)
            finally:
                output_queue.put(None)

        reader = threading.Thread(target=read_output, daemon=True, name=f"asm-output-{scan_id}")
        reader.start()
        stream_closed = False

        while not stream_closed or proc.poll() is None:
            try:
                line = output_queue.get(timeout=0.15)
            except queue.Empty:
                line = ""
            if line is None:
                stream_closed = True
            elif line:
                clean = line.rstrip()
                if clean:
                    log_lines.append(clean)
                    if len(log_lines) > 250:
                        log_lines = log_lines[-250:]
                    current_progress, stage_title, detail_msg = stage_from_line(clean, current_progress)
                    current_stage = stage_title
                    current_detail = detail_msg

                    # Time-based smooth progression
                    elapsed = time.monotonic() - start
                    time_based = min(88, 10 + int(elapsed / 3.5))
                    current_progress = max(current_progress, time_based)

                    update_job(
                        scan_id,
                        progress=min(current_progress, 89),
                        stage=current_stage,
                        detail=current_detail,
                        logs=log_lines[-100:]
                    )

            if time.monotonic() - start > timeout_seconds:
                proc.kill()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                update_job(scan_id, status="failed", progress=current_progress, stage="Scan timed out", logs=log_lines[-100:], error=f"Scan exceeded {timeout_seconds} seconds and was stopped.")
                database.record_scan_completion(scan_id, "failed", round(time.monotonic() - start, 2))
                return

        rc = proc.wait()
        duration = time.monotonic() - start
        success_marker = any("results saved to subfolder" in line.lower() for line in log_lines)

        if rc != 0 or not success_marker:
            recent = "\n".join(log_lines[-15:])
            error = "ASM did not produce a completed result set."
            if not log_lines:
                error += " The scanner returned no output."
            elif recent:
                error += " Last scanner output:\n" + recent[-1800:]
            update_job(scan_id, status="failed", progress=current_progress, stage="Scanner did not complete", logs=log_lines[-100:], error=error, duration_seconds=round(duration, 2))
            database.record_scan_completion(scan_id, "failed", round(duration, 2))
            return

        set_stage(scan_id, 92, "Building report", "Parsing and structuring result datasets")
        report = parse_results(output_root, target, duration, mode=mode)
        set_stage(scan_id, 97, "Packaging download", "Generating report ZIP archive")
        zip_path = zip_results(output_root, scan_id)

        # Save to SQLite History first
        database.record_scan_completion(
            scan_id=scan_id,
            status="completed",
            duration_seconds=round(duration, 2),
            summary=report,
            zip_name=zip_path.name,
            zip_size_bytes=zip_path.stat().st_size
        )

        update_job(
            scan_id,
            status="completed",
            progress=100,
            stage="Scan complete",
            detail="Your surface mapping report is ready.",
            logs=log_lines[-100:],
            summary=report,
            zip_name=zip_path.name,
            zip_size_bytes=zip_path.stat().st_size,
            duration_seconds=round(duration, 2),
            completed_at=utc_now(),
        )


    except Exception as exc:
        update_job(scan_id, status="failed", stage="Unexpected scan error", error=f"{type(exc).__name__}: {exc}")
        database.record_scan_completion(scan_id, "failed", round(time.monotonic() - start, 2))


# ---------------- API Endpoints ----------------

@app.get("/api/auth/config")
def auth_config() -> dict[str, Any]:
    return {
        "google_client_id": GOOGLE_CLIENT_ID,
        "demo_available": True
    }


@app.post("/api/auth/google")
def google_auth(payload: GoogleAuthRequest, response: Response) -> dict[str, Any]:
    # 1. Real Google credential verification (if token supplied)
    if payload.credential:
        try:
            resp = requests.get(f"https://oauth2.googleapis.com/tokeninfo?id_token={payload.credential}", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                email = data.get("email")
                name = data.get("name", email.split("@")[0] if email else "User")
                picture = data.get("picture", "")
                google_id = data.get("sub", "")
                user = database.get_or_create_user(email=email, name=name, picture=picture, google_id=google_id)
                response.set_cookie(key="asm_user_id", value=user["id"], httponly=True, max_age=86400 * 30, samesite="lax")
                return {"ok": True, "user": user}
        except Exception:
            pass

    # 2. Demo Google Auth (instant seamless test mode)
    demo_email = (payload.email or "sawantmayuresh2006@gmail.com").strip().lower()
    demo_name = (payload.name or "Maya").strip()
    demo_picture = payload.picture or "https://api.dicebear.com/7.x/identicon/svg?seed=Maya"
    user = database.get_or_create_user(email=demo_email, name=demo_name, picture=demo_picture, google_id="demo_user")
    response.set_cookie(key="asm_user_id", value=user["id"], httponly=True, max_age=86400 * 30, samesite="lax")
    return {"ok": True, "user": user}


@app.get("/api/auth/me")
def get_me(current_user: Optional[dict[str, Any]] = Depends(get_current_user)) -> dict[str, Any]:
    if not current_user:
        return {"authenticated": False, "user": None}
    history = database.get_user_scans(current_user["id"], limit=5)
    return {
        "authenticated": True,
        "user": current_user,
        "total_scans": len(database.get_user_scans(current_user["id"], limit=1000)),
        "recent_scans": history
    }


@app.post("/api/auth/logout")
def logout(response: Response) -> dict[str, Any]:
    response.delete_cookie(key="asm_user_id")
    return {"ok": True}


@app.get("/api/scans/history")
def scan_history(current_user: Optional[dict[str, Any]] = Depends(get_current_user)) -> list[dict[str, Any]]:
    user_id = current_user["id"] if current_user else None
    return database.get_user_scans(user_id=user_id, limit=50)


@app.delete("/api/scans/{scan_id}")
def delete_scan_record(scan_id: str, current_user: Optional[dict[str, Any]] = Depends(get_current_user)) -> dict[str, Any]:
    user_id = current_user["id"] if current_user else None
    deleted = database.delete_scan(scan_id, user_id=user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found or unauthorized.")
    with JOBS_LOCK:
        JOBS.pop(scan_id, None)
    return {"ok": True, "deleted_id": scan_id}


@app.get("/api/health")
def health() -> dict[str, Any]:
    return preflight()


@app.post("/api/scans")
def create_scan(request: StartScanRequest, current_user: Optional[dict[str, Any]] = Depends(get_current_user)) -> dict[str, Any]:
    if not request.authorized:
        raise HTTPException(status_code=400, detail="Confirm that you are authorized to assess this target.")
    try:
        target, _ = normalize_target(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    info = preflight()
    scan_id = uuid.uuid4().hex[:12]
    user_id = current_user["id"] if current_user else None

    job = {
        "id": scan_id,
        "user_id": user_id,
        "target": target,
        "mode": request.mode,
        "status": "queued",
        "progress": 1,
        "stage": "Queued",
        "detail": f"Preparing {request.mode.title()} scan for {target}",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "logs": [],
        "summary": None,
        "error": None,
        "scanner_ready": info["ready"],
    }

    with JOBS_LOCK:
        active_count = sum(1 for item in JOBS.values() if item.get("status") in {"queued", "running"})
        if active_count >= MAX_CONCURRENT_SCANS:
            raise HTTPException(status_code=429, detail="The scanner is busy with another run. Try again when it finishes.")
        JOBS[scan_id] = job

    # Record in SQLite history
    database.record_scan_start(scan_id, target, request.mode, user_id)

    thread = threading.Thread(
        target=run_scan,
        args=(scan_id, target, request.mode, user_id),
        daemon=True,
        name=f"asm-scan-{scan_id}"
    )
    thread.start()
    return {
        "id": scan_id,
        "target": target,
        "mode": request.mode,
        "status": "queued",
        "status_url": f"/api/scans/{scan_id}"
    }


@app.get("/api/scans/{scan_id}")
def find_or_reconstruct_job(scan_id: str) -> dict[str, Any]:
    with JOBS_LOCK:
        job = JOBS.get(scan_id)
        if job:
            return dict(job)

    # Check SQLite DB first
    db_scan = database.get_scan_by_id(scan_id)
    if db_scan and db_scan.get("summary"):
        summary = db_scan["summary"]
        reconstructed = {
            "id": scan_id,
            "target": db_scan["target"],
            "mode": db_scan.get("mode", "passive"),
            "status": db_scan["status"],
            "progress": 100 if db_scan["status"] == "completed" else 0,
            "stage": "Scan complete" if db_scan["status"] == "completed" else "Failed",
            "detail": "Loaded from history.",
            "created_at": db_scan["started_at"],
            "updated_at": db_scan.get("completed_at", db_scan["started_at"]),
            "completed_at": db_scan.get("completed_at"),
            "duration_seconds": db_scan.get("duration_seconds", 0.0),
            "logs": ["Scan loaded from scan history database."],
            "summary": summary,
            "zip_name": db_scan.get("zip_name"),
            "zip_size_bytes": db_scan.get("zip_size_bytes", 0),
            "error": None,
            "scanner_ready": True,
        }
        with JOBS_LOCK:
            JOBS[scan_id] = reconstructed
        return reconstructed

    # Disk folder fallback
    matched_run = None
    if RUNS_DIR.exists():
        for p in RUNS_DIR.iterdir():
            if p.is_dir() and (p.name == scan_id or p.name.startswith(f"{scan_id}_")):
                matched_run = p
                break

    if not matched_run:
        raise HTTPException(status_code=404, detail="Scan not found.")

    subdirs = [s for s in matched_run.iterdir() if s.is_dir()]
    target_dir = max(subdirs, key=lambda d: d.stat().st_mtime) if subdirs else matched_run
    target_name = target_dir.name.split("_")[0] if "_" in target_dir.name else target_dir.name

    summary_json = matched_run / "ASM_Scan_Summary.json"
    if summary_json.is_file():
        try:
            summary = json.loads(summary_json.read_text(encoding="utf-8"))
            if "sections" not in summary:
                summary = parse_results(matched_run, target_name, summary.get("duration_seconds", 0.0))
        except Exception:
            summary = parse_results(matched_run, target_name, 0.0)
    else:
        summary = parse_results(matched_run, target_name, 0.0)

    zip_candidate = ARTIFACTS_DIR / f"asm-report-{scan_id}.zip"
    if not zip_candidate.is_file():
        try:
            zip_candidate = zip_results(matched_run, scan_id)
        except Exception:
            pass

    surfacedrift_adv = None
    adv_candidates = [
        target_dir / "surfacedrift_advanced_report.json",
        matched_run / "surfacedrift_advanced_report.json",
    ]
    for cand in adv_candidates:
        if cand.is_file():
            try:
                surfacedrift_adv = json.loads(cand.read_text(encoding="utf-8"))
                break
            except Exception:
                pass

    combined_zip = ARTIFACTS_DIR / f"surfacedrift-complete-{scan_id}.zip"
    combined_name = combined_zip.name if combined_zip.is_file() else None
    combined_size = combined_zip.stat().st_size if combined_zip.is_file() else 0

    reconstructed = {
        "id": scan_id,
        "target": target_name,
        "mode": "passive",
        "status": "completed",
        "progress": 100,
        "stage": "Scan complete",
        "detail": "Your report is ready.",
        "created_at": summary.get("completed_at", utc_now()),
        "updated_at": summary.get("completed_at", utc_now()),
        "completed_at": summary.get("completed_at", utc_now()),
        "duration_seconds": summary.get("duration_seconds", 0.0),
        "output_root": str(matched_run),
        "logs": ["Scan loaded from disk cache."],
        "summary": summary,
        "zip_name": zip_candidate.name if zip_candidate.is_file() else None,
        "zip_size_bytes": zip_candidate.stat().st_size if zip_candidate.is_file() else 0,
        "surfacedrift_advanced": surfacedrift_adv,
        "combined_zip_name": combined_name,
        "combined_zip_size": combined_size,
        "error": None,
        "scanner_ready": True,
    }
    with JOBS_LOCK:
        JOBS[scan_id] = reconstructed
    return reconstructed


@app.get("/api/scans/{scan_id}/results")
def get_scan_results(scan_id: str) -> dict[str, Any]:
    job = find_or_reconstruct_job(scan_id)
    if job.get("status") != "completed" or not job.get("summary"):
        raise HTTPException(status_code=409, detail="Results are not ready yet.")
    return job["summary"]


@app.post("/api/scans/{scan_id}/continue-surfacedrift")
async def continue_surfacedrift(scan_id: str, payload: ContinueSurfaceDriftRequest) -> dict[str, Any]:
    job = find_or_reconstruct_job(scan_id)
    if job.get("status") != "completed" or not job.get("summary"):
        raise HTTPException(status_code=400, detail="Initial reconnaissance scan must be complete before running SurfaceDrift advanced assessment.")

    summary = job["summary"]
    sections = summary.get("sections", {})
    subdomains = sections.get("subdomains", [])
    ip_records = sections.get("ip_records", [])
    ports_and_vulns = sections.get("ports_and_vulns", [])
    buckets = sections.get("buckets", [])
    email_sec = sections.get("email_security", {})

    output_root_str = job.get("output_root")
    if output_root_str:
        output_root = Path(output_root_str).resolve()
    else:
        matched = None
        if RUNS_DIR.exists():
            for p in RUNS_DIR.iterdir():
                if p.is_dir() and (p.name == scan_id or p.name.startswith(f"{scan_id}_")):
                    matched = p
                    break
        output_root = matched or (RUNS_DIR / scan_id)

    target_dirs = [p for p in output_root.iterdir() if p.is_dir()] if output_root.exists() else []
    result_dir = max(target_dirs, key=lambda p: p.stat().st_mtime) if target_dirs else output_root

    advanced_results = await run_advanced_assessment(
        scan_id=scan_id,
        target=job["target"],
        subdomains=subdomains,
        ip_records=ip_records,
        ports_and_vulns=ports_and_vulns,
        buckets_initial=buckets,
        email_sec_initial=email_sec,
        categories=payload.categories,
        output_dir=result_dir,
        artifacts_dir=ARTIFACTS_DIR,
    )

    with JOBS_LOCK:
        if scan_id in JOBS:
            JOBS[scan_id]["surfacedrift_advanced"] = advanced_results
            JOBS[scan_id]["combined_zip_name"] = advanced_results.get("combined_zip_name")
            JOBS[scan_id]["combined_zip_size"] = advanced_results.get("combined_zip_size", 0)

    database.record_surfacedrift_advanced(scan_id, advanced_results)

    return {
        "ok": True,
        "scan_id": scan_id,
        "advanced": advanced_results,
    }


@app.post("/api/scans/{scan_id}/continue-surfacedrift-stream")
async def continue_surfacedrift_stream(scan_id: str, payload: ContinueSurfaceDriftRequest):
    job = find_or_reconstruct_job(scan_id)
    if job.get("status") != "completed" or not job.get("summary"):
        raise HTTPException(
            status_code=400,
            detail="Initial reconnaissance scan must be complete before running SurfaceDrift advanced assessment.",
        )

    summary = job["summary"]
    sections = summary.get("sections", {})
    subdomains = sections.get("subdomains", [])
    ip_records = sections.get("ip_records", [])
    ports_and_vulns = sections.get("ports_and_vulns", [])
    buckets = sections.get("buckets", [])
    email_sec = sections.get("email_security", {})

    output_root_str = job.get("output_root")
    if output_root_str:
        output_root = Path(output_root_str).resolve()
    else:
        matched = None
        if RUNS_DIR.exists():
            for p in RUNS_DIR.iterdir():
                if p.is_dir() and (p.name == scan_id or p.name.startswith(f"{scan_id}_")):
                    matched = p
                    break
        output_root = matched or (RUNS_DIR / scan_id)

    target_dirs = [p for p in output_root.iterdir() if p.is_dir()] if output_root.exists() else []
    result_dir = max(target_dirs, key=lambda p: p.stat().st_mtime) if target_dirs else output_root

    async def event_generator():
        log_queue = asyncio.Queue()

        def stream_log(line: str):
            log_queue.put_nowait({"type": "log", "line": line})

        async def runner():
            try:
                res = await run_advanced_assessment(
                    scan_id=scan_id,
                    target=job["target"],
                    subdomains=subdomains,
                    ip_records=ip_records,
                    ports_and_vulns=ports_and_vulns,
                    buckets_initial=buckets,
                    email_sec_initial=email_sec,
                    categories=payload.categories,
                    output_dir=result_dir,
                    artifacts_dir=ARTIFACTS_DIR,
                    on_log=stream_log,
                )
                with JOBS_LOCK:
                    if scan_id in JOBS:
                        JOBS[scan_id]["surfacedrift_advanced"] = res
                        JOBS[scan_id]["combined_zip_name"] = res.get("combined_zip_name")
                        JOBS[scan_id]["combined_zip_size"] = res.get("combined_zip_size", 0)
                database.record_surfacedrift_advanced(scan_id, res)
                await log_queue.put({"type": "done", "advanced": res})
            except Exception as e:
                logger.exception("Error in stream runner: %s", e)
                await log_queue.put({"type": "error", "error": str(e)})
            finally:
                await log_queue.put(None)

        asyncio.create_task(runner())

        while True:
            item = await log_queue.get()
            if item is None:
                break
            yield f"data: {json.dumps(item)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/scans/{scan_id}/download-combined")
def download_combined_scan(scan_id: str) -> FileResponse:
    job = find_or_reconstruct_job(scan_id)
    zip_name = job.get("combined_zip_name") or f"surfacedrift-complete-{scan_id}.zip"
    path = (ARTIFACTS_DIR / zip_name).resolve()
    if not path.is_file() or ARTIFACTS_DIR not in path.parents:
        # Fallback to single report ZIP if combined was not created
        single_zip = job.get("zip_name")
        if single_zip and (ARTIFACTS_DIR / single_zip).is_file():
            path = (ARTIFACTS_DIR / single_zip).resolve()
        else:
            raise HTTPException(status_code=404, detail="Combined assessment report archive not found.")

    return FileResponse(
        path,
        media_type="application/zip",
        filename=f"{job['target']}-surfacedrift-full-assessment-{scan_id}.zip"
    )



@app.get("/api/scans/{scan_id}/artifacts/{artifact_path:path}")
def get_scan_artifact(scan_id: str, artifact_path: str) -> FileResponse:
    job = find_or_reconstruct_job(scan_id)
    output_root_str = job.get("output_root")
    if not output_root_str:
        raise HTTPException(status_code=404, detail="Artifact storage path unavailable.")
    output_root = Path(output_root_str).resolve()
    target_dirs = [p for p in output_root.iterdir() if p.is_dir()] if output_root.exists() else []
    result_dir = max(target_dirs, key=lambda p: p.stat().st_mtime) if target_dirs else output_root

    file_path = (result_dir / artifact_path).resolve()
    if not file_path.is_file() or result_dir not in file_path.parents and file_path != result_dir:
        file_path = (output_root / artifact_path).resolve()
        if not file_path.is_file() or output_root not in file_path.parents and file_path != output_root:
            raise HTTPException(status_code=404, detail="Artifact file not found.")

    media_type = "text/plain"
    if file_path.suffix.lower() == ".json":
        media_type = "application/json"
    elif file_path.suffix.lower() == ".csv":
        media_type = "text/csv"
    elif file_path.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"}:
        media_type = f"image/{file_path.suffix.lower().lstrip('.')}"
    return FileResponse(file_path, media_type=media_type, filename=file_path.name)


@app.get("/api/scans/{scan_id}/download")
def download_scan(scan_id: str) -> FileResponse:
    job = find_or_reconstruct_job(scan_id)
    if job.get("status") != "completed" or not job.get("zip_name"):
        raise HTTPException(status_code=409, detail="The report is not ready yet.")
    path = (ARTIFACTS_DIR / job["zip_name"]).resolve()
    if not path.is_file() or ARTIFACTS_DIR not in path.parents:
        raise HTTPException(status_code=404, detail="The report archive could not be found.")
    return FileResponse(path, media_type="application/zip", filename=f"{job['target']}-asm-report-{scan_id}.zip")


@app.get("/")
def landing() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/scan")
def scan_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.exception_handler(404)
async def not_found(_request: Request, exc):
    path = _request.url.path
    if not path.startswith("/api/") and not path.startswith("/static/"):
        return FileResponse(STATIC_DIR / "index.html")
    return JSONResponse(status_code=404, content={"detail": "Not found"})



if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8000")), reload=False)
