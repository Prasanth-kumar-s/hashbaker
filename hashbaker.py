#!/usr/bin/env python3
"""
Tool: HashBaker
Author: Prasanth-kumar-s
GitHub: https://github.com/Prasanth-kumar-s
Version: 2.1

Behavior:
 - Installs required system packages if run as root (silent).
 - Ensures Python dependency `pyhanko` for PDF extraction (pip --user) if needed.
 - Extracts hashes from PDF, ZIP, RAR, 7z, Office, PCAP, NTDS where extractors exist.
 - Outputs minimal information:
     - On success: banner, "Extraction successful." then next line the output path.
     - On failure: banner, "Extraction failed." then next line a short reason.
"""

from __future__ import annotations
import os
import sys
import shutil
import subprocess
import urllib.request
from pathlib import Path
from typing import Optional

# ---------------- Config ----------------
AUTHOR = "Prasanth-kumar-s"
GITHUB = "Prasanth-kumar-s"
TOOL_NAME = "HashBaker"
VERSION = "2.1"

REQUIRED_TOOLS = [
    "john",
    "hashcat",
    "hcxtools",
    "p7zip-full",
    "unzip",
    "unrar-free",
    "perl",
    "file",
    "poppler-utils",
]

PDF2JOHN_RAW = "https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/pdf2john.py"
SEVENZ2HASHCAT_RAW = "https://raw.githubusercontent.com/philsmd/7z2hashcat/master/7z2hashcat.pl"

BASE_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = BASE_DIR / "helper_scripts"
SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------- Utilities ----------------
def run_quiet(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=check)
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127)

def run_capture(cmd: list[str]) -> Optional[bytes]:
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if res.returncode == 0 and res.stdout:
            return res.stdout
    except Exception:
        pass
    return None

def is_root() -> bool:
    return os.geteuid() == 0

def which(prog: str) -> Optional[str]:
    return shutil.which(prog)

def download_raw(url: str, dest: Path, timeout: int = 15) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if getattr(resp, "status", 200) != 200:
                return False
            data = resp.read()
        dest.write_bytes(data)
        dest.chmod(dest.stat().st_mode | 0o100)  # add owner execute
        return True
    except Exception:
        return False

# ---------------- Embedded PDF extractor (pyhanko-based) ----------------
class SecurityRevision:
    revisions = {2: 32, 3: 32, 4: 32, 5: 48, 6: 48}
    @classmethod
    def get_key_length(cls, revision):
        return cls.revisions.get(revision, 48)

class PdfHashExtractor:
    def __init__(self, file_name: str, strict: bool = False):
        from pyhanko.pdf_utils.misc import PdfReadError  # type: ignore
        from pyhanko.pdf_utils.reader import PdfFileReader  # type: ignore
        self.PdfReadError = PdfReadError
        self.PdfFileReader = PdfFileReader

        self.file_name = file_name
        with open(file_name, "rb") as doc:
            self.pdf = self.PdfFileReader(doc, strict=strict)
            self.encrypt_dict = self.pdf.encrypt_dict
            if not self.encrypt_dict:
                raise RuntimeError("File not encrypted")
            self.algorithm = self.encrypt_dict.get("/V")
            self.length = self.encrypt_dict.get("/Length", 40)
            self.permissions = self.encrypt_dict["/P"]
            self.revision = self.encrypt_dict["/R"]

    @property
    def document_id(self) -> bytes:
        return self.pdf.document_id[0]

    @property
    def encrypt_metadata(self) -> str:
        return str(int(self.pdf.security_handler.encrypt_metadata))

    def parse(self) -> str:
        passwords = self.get_passwords()
        fields = [
            f"$pdf${self.algorithm}",
            self.revision,
            self.length,
            self.permissions,
            self.encrypt_metadata,
            len(self.document_id),
            self.document_id.hex(),
            passwords,
        ]
        return "*".join(map(str, fields))

    def get_passwords(self) -> str:
        passwords = []
        keys = ("udata", "odata", "oeseed", "ueseed")
        max_key_length = SecurityRevision.get_key_length(self.revision)
        for key in keys:
            if data := getattr(self.pdf.security_handler, key):
                data: bytes = data[:max_key_length]
                passwords.extend([str(len(data)), data.hex()])
        return "*".join(passwords)

def ensure_pyhanko() -> bool:
    try:
        import pyhanko  # noqa: F401
        return True
    except Exception:
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "--user", "pyhanko"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            import importlib
            importlib.invalidate_caches()
            try:
                import pyhanko  # noqa: F401
                return True
            except Exception:
                return False
        except Exception:
            return False

# ---------------- Type detection ----------------
def detect_type(path: Path) -> str:
    ext = path.suffix.lower().lstrip(".")
    if ext == "pdf":
        return "pdf"
    if ext in ("doc","docx","xls","xlsx","ppt","pptx"):
        return "office"
    if ext == "zip":
        return "zip"
    if ext == "rar":
        return "rar"
    if ext == "7z":
        return "7z"
    if ext in ("pcap","cap","pcapng"):
        return "pcap"
    if path.name.lower().endswith("ntds.dit"):
        return "ntds"
    f = which("file")
    if f:
        try:
            out = subprocess.run([f, "-b", "--mime-type", str(path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            mime = out.stdout.decode().strip().lower()
            if "pdf" in mime:
                return "pdf"
            if "pcap" in mime:
                return "pcap"
            if "zip" in mime:
                return "zip"
            if "rar" in mime or "x-rar" in mime:
                return "rar"
            if "7z" in mime:
                return "7z"
        except Exception:
            pass
    return "unknown"

# ---------------- Auto-install ----------------
def auto_install():
    if not is_root():
        print("Error: must run as root to install dependencies.")
        sys.exit(1)
    run_quiet(["apt-get", "update"], check=True)
    run_quiet(["apt-get", "install", "-y"] + REQUIRED_TOOLS, check=True)

# ---------------- Extraction helpers ----------------
def write_to_unified_hashfile(src: Path, data: bytes) -> Path:
    out = src.with_suffix(".hash")
    out.write_bytes(data)
    return out

def extract_pdf(path: Path) -> Optional[Path]:
    if not ensure_pyhanko():
        return None
    try:
        extractor = PdfHashExtractor(str(path))
        txt = extractor.parse().encode()
        return write_to_unified_hashfile(path, txt)
    except Exception:
        return None

def extract_with_john_tool(tool: str, path: Path) -> Optional[Path]:
    exe = which(tool)
    if not exe:
        return None
    res = run_capture([exe, str(path)])
    if res:
        return write_to_unified_hashfile(path, res)
    return None

def extract_7z(path: Path) -> Optional[Path]:
    local = SCRIPTS_DIR / "7z2hashcat.pl"
    if not which("7z2hashcat.pl") and not local.exists():
        download_raw(SEVENZ2HASHCAT_RAW, local)
    helper = which("7z2hashcat.pl") or (str(local) if local.exists() else None)
    if helper:
        if helper.endswith(".pl"):
            cmd = ["perl", helper, str(path)]
        else:
            cmd = [helper, str(path)]
        res = run_capture(cmd)
        if res:
            return write_to_unified_hashfile(path, res)
    return None

def extract_pcap(path: Path) -> Optional[Path]:
    ex = which("hcxpcapngtool") or which("hcxpcaptool")
    if not ex:
        return None
    outname = path.with_suffix(".hash")
    try:
        run_quiet([ex, "-o", str(outname), str(path)])
        if outname.exists():
            return outname
    except Exception:
        pass
    return None

def extract_hash(path: Path) -> Optional[Path]:
    t = detect_type(path)
    if t == "pdf":
        return extract_pdf(path)
    if t == "office":
        return extract_with_john_tool("office2john.py", path) or extract_with_john_tool("office2john", path)
    if t == "zip":
        return extract_with_john_tool("zip2john", path)
    if t == "rar":
        return extract_with_john_tool("rar2john", path)
    if t == "7z":
        return extract_7z(path)
    if t == "pcap":
        return extract_pcap(path)
    if t == "ntds":
        return extract_with_john_tool("ntds2john.py", path) or extract_with_john_tool("ntds2john", path)
    return None

# ---------------- Banner & minimal output ----------------
def banner() -> str:
    return (
        "\033[1;36m\n"
        "ooooo   ooooo       .o.        .oooooo..o ooooo   ooooo      oooooooooo.        .o.       oooo    oooo oooooooooooo ooooooooo.   \n"
        "`888'   `888'      .888.      d8P'    `Y8 `888'   `888'      `888'   `Y8b      .888.      `888   .8P'  `888'     `8 `888   `Y88. \n"
        " 888     888      .8\"888.     Y88bo.       888     888        888     888     .8\"888.      888  d8'     888          888   .d88' \n"
        " 888ooooo888     .8' `888.     `\"Y8888o.   888ooooo888        888oooo888'    .8' `888.     88888[       888oooo8     888ooo88P'  \n"
        " 888     888    .88ooo8888.        `\"Y88b  888     888        888    `88b   .88ooo8888.    888`88b.     888    \"     888`88b.    \n"
        " 888     888   .8'     `888.  oo     .d8P  888     888        888    .88P  .8'     `888.   888  `88b.   888       o  888  `88b.  \n"
        "o888o   o888o o88o     o8888o 8\"\"88888P'  o888o   o888o      o888bood8P'  o88o     o8888o o888o  o888o o888ooooood8 o888o  o888o \n"
        "\033[0m"
        f"\033[1;33m\n {TOOL_NAME}  -  Version {VERSION} \n Author: {AUTHOR}   GitHub: {GITHUB}\033[0m\n"
    )

def print_success(out: Path):
    print(banner())
    print("Extraction successful.")
    print(str(out))
    sys.exit(0)

def print_failure(reason: Optional[str] = None):
    print(banner())
    print("Extraction failed.")
    if reason:
        print(reason)
    sys.exit(2)

# ---------------- Main ----------------
def main():
    if len(sys.argv) != 2 or sys.argv[1] in ("-h", "--help"):
        print(banner())
        print(f"Usage: {sys.argv[0]} <protected_file_path>")
        sys.exit(0)

    src = Path(sys.argv[1]).expanduser().resolve()
    if not src.exists():
        print_failure("Error: file not found.")

    try:
        auto_install()
    except Exception:
        # silent - proceed with available tools
        pass

    out = extract_hash(src)
    if out:
        print_success(out)
    else:
        t = detect_type(src)
        if t == "pdf":
            print_failure("PDF extraction failed: pyhanko missing or unsupported PDF protection.")
        elif t == "pcap":
            print_failure("PCAP extraction failed: hcxpcapngtool missing or no WPA handshake present.")
        else:
            print_failure("Extractor missing or file format unsupported.")

if __name__ == "__main__":
    main()
