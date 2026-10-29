#!/usr/bin/env python3
"""Opt-in, non-root LLDB lifecycle check against an owned disposable program."""

import argparse
import ast
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("Run this fixture as a normal user, never with sudo")
    probe = (args.source / "cmd/wxkey/main.go").read_text().split(
        "const pbkdfProbePython = `", 1)[1].split("`", 1)[0]
    names = {"owner_launch_info", "verify_process_owner", "wait_for_stop", "launch_as_owner"}
    functions = [node for node in ast.parse(probe).body
                 if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in functions} != names:
        parser.error("Source does not contain the reviewed lifecycle candidate")
    lldb_path = subprocess.check_output(["/usr/bin/lldb", "-P"], text=True, timeout=10).strip()
    sys.path.insert(0, lldb_path)
    import lldb

    namespace = {"os": os, "pwd": pwd, "time": time, "lldb": lldb}
    exec(compile(ast.Module(body=functions, type_ignores=[]), "candidate-lifecycle", "exec"), namespace)
    with tempfile.TemporaryDirectory(prefix="rion-lldb-fixture-") as folder:
        root = Path(folder)
        source = root / "fixture.c"
        source.write_text("#include <unistd.h>\nint main(void) { sleep(15); return 0; }\n")
        executable = root / "fixture"
        subprocess.run(["/usr/bin/clang", "-g", str(source), "-o", str(executable)],
                       check=True, timeout=30, capture_output=True)
        debugger = lldb.SBDebugger.Create()
        debugger.SetAsync(True)
        process = None
        try:
            target = debugger.CreateTarget(str(executable))
            process, listener = namespace["launch_as_owner"](target, str(root), time.monotonic() + 10)
            previous = process.GetStopID()
            if process.Continue().Fail():
                raise RuntimeError("fixture_continue_failed")
            started = time.monotonic()
            stopped = namespace["wait_for_stop"](process, listener, started + 1.5, previous)
            elapsed = time.monotonic() - started
            if stopped or elapsed > 3.5:
                raise RuntimeError("fixture_deadline_failed")
            print(json.dumps({"fixture": "normal_user_only", "identity_verified": True,
                              "wait_elapsed_seconds": round(elapsed, 3), "deadline_verified": True,
                              "wechat_accessed": False, "root_to_user_launch_tested": False}))
        finally:
            if process is not None and process.IsValid():
                process.Kill()
            lldb.SBDebugger.Destroy(debugger)


if __name__ == "__main__":
    main()
