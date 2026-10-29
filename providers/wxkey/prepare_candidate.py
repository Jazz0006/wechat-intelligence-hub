#!/usr/bin/env python3
"""Prepare pinned, patched source locally. Never build, run or install a provider."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent


def unpack(archive, destination):
    with tarfile.open(archive, "r:") as bundle:
        members = bundle.getmembers()
        total = 0
        seen = set()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or ".git" in path.parts:
                raise ValueError("unsafe_archive_path")
            if not path.parts or path in seen or not (member.isfile() or member.isdir()):
                raise ValueError("unsupported_archive_entry")
            seen.add(path)
            total += member.size
            if total > 100 * 1024 * 1024:
                raise ValueError("archive_too_large")
        for member in members:
            target = destination / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with target.open("xb") as output, bundle.extractfile(member) as source:
                    while True:
                        chunk = source.read(65536)
                        if not chunk:
                            break
                        output.write(chunk)
                target.chmod(0o700 if member.mode & 0o111 else 0o600)


def prepare(source, out):
    manifest = json.loads((HERE / "candidate.json").read_text())
    patch = HERE / manifest["patch"]
    if hashlib.sha256(patch.read_bytes()).hexdigest() != manifest["patch_sha256"]:
        raise ValueError("candidate_patch_digest_mismatch")
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    # Do not let caller git overrides redirect the isolated working tree.
    for key in list(env):
        if key.startswith("GIT_") and key not in {"GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM"}:
            del env[key]

    def git(*args, cwd=None):
        return subprocess.run(["git", *args], cwd=cwd, env=env, check=True,
                              capture_output=True, text=True, timeout=30).stdout.strip()

    source = source.resolve(strict=True)
    base = manifest["base_commit"]
    if git("-C", str(source), "rev-parse", "--verify", base + "^{commit}") != base:
        raise ValueError("candidate_base_commit_mismatch")
    # Existing files, directories and symlinks must never be reused or overwritten.
    if os.path.lexists(out):
        raise ValueError("candidate_output_already_exists")
    out.mkdir(mode=0o700)
    out = out.resolve(strict=True)
    archive = out / "upstream.tar"
    work = out / "source"
    work.mkdir(mode=0o700)
    git("-C", str(source), "archive", "--format=tar", "--output=" + str(archive), base)
    unpack(archive, work)
    archive.unlink()
    git("init", "--quiet", str(work))
    git("apply", "--check", "--whitespace=error", str(patch), cwd=work)
    git("apply", "--whitespace=error", str(patch), cwd=work)
    receipt = dict(manifest, source_prepared=True, provider_built=False, provider_executed=False,
                   installed=False)
    receipt["source_hashes"] = {
        path: hashlib.sha256((work / path).read_bytes()).hexdigest()
        for path in ("cmd/wxkey/main.go", "go.mod", "go.sum",
                     "cmd/wxkey/recovery_candidate_test.go", "tests/test_launch_candidate.py")
    }
    (out / "candidate-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="Existing local upstream checkout")
    parser.add_argument("--out", type=Path, required=True, help="New private directory; parent must exist")
    args = parser.parse_args()
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        parser.error("Prepare as a normal user, not root")
    receipt = prepare(args.source, args.out)
    print(json.dumps({key: receipt[key] for key in
                      ("status", "source_prepared", "provider_built", "provider_executed", "installed")}))


if __name__ == "__main__":
    main()
