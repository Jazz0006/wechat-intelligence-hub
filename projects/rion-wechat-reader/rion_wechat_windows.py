"""Experimental Windows x64 acquisition; read-only, same-user, explicit opt-in.

No injection, process writes, privilege adjustment, app restart, or network calls.
Memory candidates never leave the worker. Only database-verified raw keys are
saved using the Reader's private-output policy. This is not a version guarantee.
"""
from __future__ import annotations

import ctypes as C
import hashlib
import hmac
import json
import multiprocessing as MP
import os
from pathlib import Path
import platform
import re
import struct
import tempfile
import time

import rion_wechat_reader as reader


class WindowsAccessError(Exception):
    """Messages are fixed public codes, never OS errors or candidate bytes."""


def write_private_json(path: Path, value: dict) -> None:
    """Publish without replacing an existing plan, result, or material file."""
    path = private_path(path)
    reader.prepare_private_output(path, chmod_parent=False)
    if not reader.safe_mode(path.parent):
        raise WindowsAccessError("unsafe_output_permissions")
    fd, name = tempfile.mkstemp(prefix=".windows-stage-", dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            reader.protect_new_file(temp)
            json.dump(value, output, ensure_ascii=False)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temp, path)
        except FileExistsError:
            raise WindowsAccessError("output_exists_not_overwritten") from None
    finally:
        temp.unlink(missing_ok=True)


def require_windows() -> None:
    if platform.system() != "Windows":
        raise WindowsAccessError("windows_host_required")
    if struct.calcsize("P") != 8 or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise WindowsAccessError("windows_x64_required")


def private_path(value: Path) -> Path:
    path = value.expanduser().absolute()
    for item in (path, *path.parents):
        if item.is_symlink() or getattr(item, "is_junction", lambda: False)():
            raise WindowsAccessError("reparse_path_rejected")
        if os.name == "nt" and item.exists() and item.stat().st_file_attributes & 0x400:
            raise WindowsAccessError("reparse_path_rejected")
    if str(path).startswith("\\\\"):
        raise WindowsAccessError("local_path_required")
    return path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with private_path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class MemoryInfo(C.Structure):
    # MEMORY_BASIC_INFORMATION for 64-bit Windows, including natural alignment.
    _fields_ = [("base", C.c_void_p), ("allocation_base", C.c_void_p),
                ("allocation_protect", C.c_uint32), ("partition", C.c_uint16),
                ("size", C.c_size_t), ("state", C.c_uint32),
                ("protect", C.c_uint32), ("type", C.c_uint32)]


class FileTime(C.Structure):
    _fields_ = [("low", C.c_uint32), ("high", C.c_uint32)]


class VersionInfo(C.Structure):
    _fields_ = [(name, C.c_uint32) for name in (
        "signature", "structure_version", "file_ms", "file_ls", "product_ms",
        "product_ls", "flags_mask", "flags", "os", "type", "subtype", "date_ms", "date_ls")]


class WindowsProcess:
    """Win32 boundary. All process handles request only QUERY_INFORMATION/VM_READ."""
    def __init__(self, pid: int, *, read_memory: bool = False):
        require_windows()
        if pid <= 0:
            raise WindowsAccessError("invalid_process_id")
        self.pid, self.handle, self.read_memory = pid, None, read_memory
        self.kernel = C.WinDLL("kernel32", use_last_error=True)
        self.advapi = C.WinDLL("advapi32", use_last_error=True)
        self.psapi = C.WinDLL("psapi", use_last_error=True)
        self.version = C.WinDLL("version", use_last_error=True)
        self._bind()
        self.handle = self.kernel.OpenProcess(0x0400 | (0x0010 if read_memory else 0), False, pid)
        if not self.handle:
            raise WindowsAccessError("process_read_access_denied")
        try:
            if self._sid(self.handle) != self._sid(self.kernel.GetCurrentProcess()):
                raise WindowsAccessError("process_owner_mismatch")
            machine, native = C.c_uint16(), C.c_uint16()
            if not self.kernel.IsWow64Process2(self.handle, C.byref(machine), C.byref(native)):
                raise WindowsAccessError("process_architecture_unverified")
            if machine.value != 0 or native.value != 0x8664:
                raise WindowsAccessError("process_x64_required")
        except BaseException:
            self.close()
            raise

    def _bind(self) -> None:
        H, D, B, P, S = C.c_void_p, C.c_uint32, C.c_int32, C.c_void_p, C.c_size_t
        signatures = [
            (self.kernel, "OpenProcess", [D, B, D], H),
            (self.kernel, "CloseHandle", [H], B),
            (self.kernel, "GetCurrentProcess", [], H),
            (self.kernel, "QueryFullProcessImageNameW", [H, D, C.c_wchar_p, C.POINTER(D)], B),
            (self.kernel, "GetProcessTimes", [H, P, P, P, P], B),
            (self.kernel, "IsWow64Process2", [H, P, P], B),
            (self.kernel, "VirtualQueryEx", [H, P, P, S], S),
            (self.kernel, "ReadProcessMemory", [H, P, P, S, C.POINTER(S)], B),
            (self.kernel, "LocalFree", [H], H),
            (self.advapi, "OpenProcessToken", [H, D, C.POINTER(H)], B),
            (self.advapi, "GetTokenInformation", [H, D, P, D, C.POINTER(D)], B),
            (self.advapi, "ConvertSidToStringSidW", [P, C.POINTER(C.c_wchar_p)], B),
            (self.psapi, "EnumProcessModulesEx", [H, P, D, C.POINTER(D), D], B),
            (self.psapi, "GetModuleFileNameExW", [H, H, C.c_wchar_p, D], D),
            (self.version, "GetFileVersionInfoSizeW", [C.c_wchar_p, P], D),
            (self.version, "GetFileVersionInfoW", [C.c_wchar_p, D, D, P], B),
            (self.version, "VerQueryValueW", [P, C.c_wchar_p, C.POINTER(P), C.POINTER(D)], B),
        ]
        for library, name, args, result in signatures:
            function = getattr(library, name)
            function.argtypes, function.restype = args, result

    def close(self) -> None:
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _sid(self, process) -> str:
        token, needed = C.c_void_p(), C.c_uint32()
        if not self.advapi.OpenProcessToken(process, 0x0008, C.byref(token)):
            raise WindowsAccessError("process_owner_unverified")
        try:
            self.advapi.GetTokenInformation(token, 1, None, 0, C.byref(needed))
            if not 0 < needed.value <= 65536:
                raise WindowsAccessError("process_owner_unverified")
            buffer = C.create_string_buffer(needed.value)
            if not self.advapi.GetTokenInformation(token, 1, buffer, needed.value, C.byref(needed)):
                raise WindowsAccessError("process_owner_unverified")
            sid = C.cast(buffer, C.POINTER(C.c_void_p))[0]
            text = C.c_wchar_p()
            if not self.advapi.ConvertSidToStringSidW(sid, C.byref(text)):
                raise WindowsAccessError("process_owner_unverified")
            try:
                return text.value
            finally:
                self.kernel.LocalFree(C.cast(text, C.c_void_p))
        finally:
            self.kernel.CloseHandle(token)

    def file_version(self, path: Path) -> str:
        count = self.version.GetFileVersionInfoSizeW(str(path), None)
        if not 0 < count <= 4 * 1024 * 1024:
            raise WindowsAccessError("file_version_unverified")
        buffer = C.create_string_buffer(count)
        if not self.version.GetFileVersionInfoW(str(path), 0, count, buffer):
            raise WindowsAccessError("file_version_unverified")
        pointer, length = C.c_void_p(), C.c_uint32()
        if not self.version.VerQueryValueW(buffer, "\\", C.byref(pointer), C.byref(length)):
            raise WindowsAccessError("file_version_unverified")
        if length.value < C.sizeof(VersionInfo):
            raise WindowsAccessError("file_version_unverified")
        info = C.cast(pointer, C.POINTER(VersionInfo)).contents
        if info.signature != 0xFEEF04BD:
            raise WindowsAccessError("file_version_unverified")
        return ".".join(map(str, (info.file_ms >> 16, info.file_ms & 65535,
                                 info.file_ls >> 16, info.file_ls & 65535)))

    def identity(self) -> dict:
        path, length = C.create_unicode_buffer(32768), C.c_uint32(32768)
        if not self.kernel.QueryFullProcessImageNameW(self.handle, 0, path, C.byref(length)):
            raise WindowsAccessError("process_identity_unverified")
        times = [FileTime() for _ in range(4)]
        if not self.kernel.GetProcessTimes(self.handle, *(C.byref(t) for t in times)):
            raise WindowsAccessError("process_identity_unverified")
        modules, needed = (C.c_void_p * 2048)(), C.c_uint32()
        if not self.psapi.EnumProcessModulesEx(self.handle, modules, C.sizeof(modules), C.byref(needed), 3):
            raise WindowsAccessError("loaded_dll_unverified")
        if needed.value > C.sizeof(modules):
            raise WindowsAccessError("loaded_dll_unverified")
        dlls = []
        for module in modules[:needed.value // C.sizeof(C.c_void_p)]:
            name = C.create_unicode_buffer(32768)
            if self.psapi.GetModuleFileNameExW(self.handle, module, name, len(name)):
                file = Path(name.value)
                if file.name.casefold() in {"weixin.dll", "wechatwin.dll"}:
                    dlls.append(private_path(file))
        if len(dlls) != 1:
            raise WindowsAccessError("unique_wechat_dll_required")
        executable = private_path(Path(path.value))
        if executable.name.casefold() not in {"weixin.exe", "wechat.exe"}:
            raise WindowsAccessError("wechat_process_required")
        version = self.file_version(dlls[0])
        if not version.startswith("4."):
            raise WindowsAccessError("wechat_4_required")
        return {"pid": self.pid, "created": times[0].low | times[0].high << 32,
                "owner_sid": self._sid(self.handle), "executable": str(executable),
                "exe_sha256": sha256_file(executable), "dll": str(dlls[0]),
                "dll_sha256": sha256_file(dlls[0]), "dll_version": version}

    def blocks(self, deadline: float, max_bytes: int, counts: dict):
        if not self.read_memory:
            raise WindowsAccessError("process_read_confirmation_required")
        address, scanned = 0, 0
        while address < 1 << 47 and time.monotonic() < deadline:
            info = MemoryInfo()
            if not self.kernel.VirtualQueryEx(self.handle, address, C.byref(info), C.sizeof(info)):
                if C.get_last_error() == 87:  # end of address space
                    return
                raise WindowsAccessError("memory_query_failed")
            base, size = int(info.base or 0), int(info.size)
            if size <= 0 or base + size <= address:
                raise WindowsAccessError("invalid_memory_region")
            address = base + size
            if info.state != 0x1000 or info.protect & (0x100 | 0x01) or not info.protect & 0xEE:
                continue
            tail = b""
            for offset in range(0, size, 1024 * 1024):
                if time.monotonic() >= deadline or scanned >= max_bytes:
                    counts["scan_truncated"] = True
                    return
                length = min(1024 * 1024, size - offset, max_bytes - scanned)
                buffer, read = C.create_string_buffer(length), C.c_size_t()
                okay = self.kernel.ReadProcessMemory(self.handle, base + offset, buffer, length, C.byref(read))
                scanned += length  # bound attempted bytes, including inaccessible pages
                counts["bytes_attempted"] = scanned
                if not okay or read.value != length:
                    tail = b""
                    counts["unreadable_blocks"] += 1
                    continue
                block = tail + buffer.raw
                counts["bytes_read"] += length
                yield block
                tail = block[-8192:]
        if time.monotonic() >= deadline:
            counts["scan_truncated"] = True


def database_pages(root: Path, max_files: int = 500) -> tuple[Path, list[tuple[Path, bytes]]]:
    root = private_path(root)
    if (root / "db_storage").is_dir():
        root /= "db_storage"
    if root.name != "db_storage" or not all((root / name).is_dir() for name in ("contact", "session", "message")):
        raise WindowsAccessError("single_account_storage_required")
    pages, inspected = [], 0
    def denied(_):
        raise WindowsAccessError("database_read_access_denied")
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=denied):
        for name in dirs:
            private_path(Path(directory) / name)
        for name in sorted(files):
            if not name.lower().endswith(".db"):
                continue
            inspected += 1
            if inspected > max_files:
                raise WindowsAccessError("database_scan_limit")
            file = private_path(Path(directory) / name)
            if not file.is_file():
                raise WindowsAccessError("database_not_regular_file")
            with file.open("rb") as source:
                page = source.read(4096)
            if page.startswith(b"SQLite format 3\x00"):
                continue
            if len(page) != 4096:
                raise WindowsAccessError("database_page_unreadable")
            pages.append((file, page))
    if not pages:
        raise WindowsAccessError("encrypted_database_required")
    return root, pages


def page_fingerprints(root: Path, pages: list) -> dict:
    return {str(path.relative_to(root)): hashlib.sha256(page).hexdigest() for path, page in pages}


def load_profile(path: Path | None, identity: dict) -> dict | None:
    if path is None:
        return None
    path = private_path(path)
    if path.stat().st_size > 65536:
        raise WindowsAccessError("invalid_scan_profile")
    profile = json.loads(path.read_text(encoding="utf-8-sig"))
    if (not isinstance(profile, dict) or profile.get("schema_version") != 1 or profile.get("dll_sha256") != identity["dll_sha256"]
            or profile.get("dll_version") != identity["dll_version"]):
        raise WindowsAccessError("profile_build_mismatch")
    rules = profile.get("rules")
    if not isinstance(rules, list) or not 1 <= len(rules) <= 8:
        raise WindowsAccessError("invalid_scan_profile")
    for rule in rules:
        try:
            pattern = bytes.fromhex(rule["pattern_hex"])
            length, offset = rule["length"], rule["offset"]
            xor = bytes.fromhex(rule.get("xor_hex", ""))
        except (KeyError, ValueError, TypeError):
            raise WindowsAccessError("invalid_scan_profile") from None
        if (not 8 <= len(pattern) <= 128 or length not in (32, 64)
                or type(offset) is not int or abs(offset) > 4096
                or rule.get("mode") not in {"raw_key", "password"}
                or rule.get("encoding", "binary") not in {"binary", "hex"}
                or len(xor) > 64):
            raise WindowsAccessError("invalid_scan_profile")
    return profile


def candidates(block: bytes, profile: dict | None):
    # Delimited SQLCipher raw literals. Bare arbitrary memory isn't treated as a key.
    for match in re.finditer(rb"[xX]'([0-9a-fA-F]{64}|[0-9a-fA-F]{96})'", block):
        raw = bytes.fromhex(match[1].decode("ascii"))
        yield "raw_key", raw[:32], raw[32:] or None
    for rule in (profile or {}).get("rules", []):
        pattern, cursor = bytes.fromhex(rule["pattern_hex"]), 0
        while True:
            position = block.find(pattern, cursor)
            if position < 0:
                break
            cursor = position + 1
            start, size = position + rule["offset"], rule["length"]
            if start < 0 or start + size > len(block):
                continue
            raw = block[start:start + size]
            if rule.get("encoding", "binary") == "hex":
                try:
                    raw = bytes.fromhex(raw.decode("ascii"))
                except (ValueError, UnicodeError):
                    continue
            xor = bytes.fromhex(rule.get("xor_hex", ""))
            if xor:
                raw = bytes(value ^ xor[index % len(xor)] for index, value in enumerate(raw))
            if rule["mode"] == "raw_key" and len(raw) != 32:
                continue
            yield rule["mode"], raw, None


def valid_raw_key(key: bytes, page: bytes) -> bool:
    """SQLCipher 4, 4096-byte page: reject candidates before saving anything."""
    if len(key) != 32 or len(page) != 4096:
        return False
    mac_salt = bytes(value ^ 0x3A for value in page[:16])
    mac_key = hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, 32)
    digest = hmac.new(mac_key, page[16:-64] + b"\x01\x00\x00\x00", hashlib.sha512).digest()
    return hmac.compare_digest(digest, page[-64:])


def scan(blocks, pages: list, profile: dict | None, deadline: float, limit: int, counts: dict) -> dict:
    found, seen = {}, set()
    for block in blocks:
        for mode, candidate, supplied_salt in candidates(block, profile):
            if time.monotonic() >= deadline or len(seen) >= limit:
                counts["scan_truncated"] = True
                return found
            signature = hashlib.sha256(mode.encode() + candidate + (supplied_salt or b"")).digest()
            if signature in seen:
                continue
            seen.add(signature)
            counts["candidates_checked"] += 1
            for _, page in pages:
                if time.monotonic() >= deadline:
                    counts["scan_truncated"] = True
                    return found
                salt = page[:16]
                if salt.hex() in found or supplied_salt is not None and supplied_salt != salt:
                    continue
                key = candidate if mode == "raw_key" else hashlib.pbkdf2_hmac("sha512", candidate, salt, 256000, 32)
                if valid_raw_key(key, page):
                    found[salt.hex()] = key.hex()
            if all(page[:16].hex() in found for _, page in pages):
                return found
    return found


def prepare(pid: int, root: Path, output: Path, profile_path: Path | None = None) -> dict:
    require_windows()
    output = private_path(output)
    if output.exists():
        raise WindowsAccessError("plan_exists_not_overwritten")
    if reader.sqlcipher_driver()[0] is None:
        raise WindowsAccessError("sqlcipher_driver_required")
    with WindowsProcess(pid) as process:
        identity = process.identity()  # metadata only; no ReadProcessMemory call
    root, pages = database_pages(root)
    profile = load_profile(profile_path, identity)
    plan = {"schema_version": 1, "created_at": time.time(), "identity": identity,
            "database_root": str(root), "database_pages": page_fingerprints(root, pages),
            "profile": profile, "profile_review_required": profile is not None}
    write_private_json(output, plan)
    return {"state": "authorization_required", "plan_file": str(output),
            "dll_version": identity["dll_version"], "database_count": len(pages),
            "process_memory_read": False, "experimental": True, "live_wechat_verified": False,
            "next_step": "审核进程、版本和可选profile；确认后运行windows-acquire。不会重启微信或自动提权。"}


def load_plan(path: Path) -> dict:
    path = private_path(path)
    if not path.is_file() or not reader.safe_mode(path) or not reader.safe_mode(path.parent):
        raise WindowsAccessError("unsafe_plan_permissions")
    if path.stat().st_size > 1024 * 1024:
        raise WindowsAccessError("plan_expired_or_invalid")
    plan = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(plan, dict) or plan.get("schema_version") != 1
            or type(plan.get("created_at")) not in {int, float}
            or not 0 <= time.time() - plan["created_at"] <= 900):
        raise WindowsAccessError("plan_expired_or_invalid")
    if (not isinstance(plan.get("identity"), dict) or type(plan["identity"].get("pid")) is not int
            or not isinstance(plan.get("database_root"), str)
            or not Path(plan["database_root"]).is_absolute()
            or not isinstance(plan.get("database_pages"), dict)):
        raise WindowsAccessError("plan_expired_or_invalid")
    return plan


def _capture(plan: dict, run_dir: Path, timeout: int, max_mb: int, limit: int) -> dict:
    deadline = time.monotonic() + timeout
    counts = {"bytes_attempted": 0, "bytes_read": 0, "unreadable_blocks": 0,
              "candidates_checked": 0, "scan_truncated": False}
    root, pages = database_pages(Path(plan["database_root"]))
    if page_fingerprints(root, pages) != plan["database_pages"]:
        raise WindowsAccessError("database_changed_prepare_again")
    with WindowsProcess(plan["identity"]["pid"], read_memory=True) as process:
        if process.identity() != plan["identity"]:
            raise WindowsAccessError("process_or_build_changed")
        profile = plan.get("profile")
        found = scan(process.blocks(deadline, max_mb * 1024 * 1024, counts), pages, profile, deadline, limit, counts)
        if process.identity() != plan["identity"]:
            raise WindowsAccessError("process_or_build_changed")
    if not found:
        return {"state": "no_verified_keys", "counts": counts, "configured": False}
    # A live database may have changed since prepare. Bind material to the same
    # account/salts and require the Reader's independent SQLCipher schema read.
    _, fresh = database_pages(root)
    if {p.relative_to(root): page[:16] for p, page in fresh} != {p.relative_to(root): page[:16] for p, page in pages}:
        raise WindowsAccessError("database_changed_prepare_again")
    material = run_dir / "verified-candidates.json"
    write_private_json(material, {"schema_version": 2, "db_root": str(root), "keys": found})
    verified = run_dir / "reader-keys.json"
    try:
        imported = reader.import_access_bundle(material, root, verified, verify=True, force=False, max_files=500)
    except BaseException:
        material.unlink(missing_ok=True)
        raise
    coverage = imported["verification"]["matched_database_count"]
    return {"state": "material_verified" if coverage == len(pages) else "partial_key_coverage",
            "material_file": str(material), "verified_database_count": coverage,
            "database_count": len(pages), "verification_level": "sqlite_schema_read",
            "counts": counts, "configured": False,
            "next_step": "用onboard --source显式验证并接入；部分覆盖不能称为完整历史。"}


def _capture_worker(plan, run_dir, timeout, max_mb, limit):
    # No public CLI worker entry; the parent owns the spawned process and timeout.
    try:
        result = _capture(plan, Path(run_dir), timeout, max_mb, limit)
    except WindowsAccessError as exc:
        result = {"state": "failed", "error_code": str(exc), "configured": False}
    except reader.ReaderError as exc:
        result = {"state": "failed", "error_code": exc.code, "configured": False}
    except Exception:
        result = {"state": "failed", "error_code": "windows_capture_failed", "configured": False}
    write_private_json(Path(run_dir) / "result.json", result)


def acquire(plan_file: Path, confirmed: bool, timeout: int = 60, max_mb: int = 512,
            limit: int = 256, profile_reviewed: bool = False) -> dict:
    require_windows()
    if not confirmed:
        raise WindowsAccessError("process_read_confirmation_required")
    if not 5 <= timeout <= 180 or not 1 <= max_mb <= 4096 or not 1 <= limit <= 4096:
        raise WindowsAccessError("invalid_scan_budget")
    plan_file = private_path(plan_file)
    plan = load_plan(plan_file)
    if plan.get("profile_review_required") and not profile_reviewed:
        raise WindowsAccessError("profile_review_confirmation_required")
    run_dir = plan_file.parent / (plan_file.stem + "-capture")
    try:
        run_dir.mkdir(mode=0o700)  # exclusive, including after a failure or timeout
    except FileExistsError:
        raise WindowsAccessError("attempt_exists_review_required") from None
    if not reader.windows_private_acl(run_dir, initialize=True):
        raise WindowsAccessError("unsafe_capture_permissions")
    write_private_json(run_dir / "attempt.json", {"state": "started", "created_at": time.time()})
    process = MP.get_context("spawn").Process(target=_capture_worker,
        args=(plan, str(run_dir), timeout, max_mb, limit))
    try:
        process.start()
    except (OSError, RuntimeError):
        return {"state": "worker_start_failed_review_required", "configured": False}
    process.join(timeout + 2)
    if process.is_alive():
        process.terminate()  # only our scanner; never the WeChat process
        process.join(2)
        if process.is_alive():
            process.kill()
            process.join(2)
        return {"state": "scan_timeout_review_required", "configured": False}
    result = run_dir / "result.json"
    if process.exitcode != 0 or not result.is_file() or not reader.safe_mode(result):
        return {"state": "worker_failed_review_required", "configured": False}
    return json.loads(result.read_text(encoding="utf-8"))
