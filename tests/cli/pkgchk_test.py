#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import pathlib
import subprocess
import sys
import tempfile

PKGCHK = pathlib.Path(sys.argv[1])
FIXTURE = pathlib.Path(sys.argv[2])


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def create_store(path: pathlib.Path):
    result = subprocess.run(
        [str(FIXTURE), str(path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(result.returncode == 0, result.stderr)
    arguments = result.stdout.strip().split()
    require(len(arguments) == 10, "fixture must emit five identity options")
    return arguments


def run(root: pathlib.Path, store: pathlib.Path, binding_args, *args):
    return subprocess.run(
        [
            str(PKGCHK),
            "-r",
            str(root),
            "--canonical-store",
            str(store),
            *binding_args,
            *args,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


with tempfile.TemporaryDirectory(prefix="libpkgaudit-cli.") as temporary:
    temporary_path = pathlib.Path(temporary)
    root = temporary_path / "target"
    store = temporary_path / "state"
    (root / "etc").mkdir(parents=True)
    (root / "etc/alpha").write_text("ok\n", encoding="utf-8")
    (root / "usr/lib").mkdir(parents=True)
    (root / "usr/lib/target").write_text("target\n", encoding="utf-8")
    binding_args = create_store(store)

    result = run(root, store, binding_args, "-d", "alpha")
    require(result.returncode == 0, result.stderr)

    (root / "etc/alpha").unlink()
    result = run(root, store, binding_args, "-d", "alpha")
    require(result.returncode == 1, result.stderr)
    require("missing object /etc/alpha" in result.stderr, result.stderr)

    (root / "etc/alpha").mkdir()
    result = run(root, store, binding_args, "-d", "alpha")
    require(result.returncode == 1, result.stderr)
    require("object class mismatch" in result.stderr, result.stderr)
    (root / "etc/alpha").rmdir()

    os.symlink("/usr/lib/target", root / "etc/alpha")
    result = run(root, store, binding_args, "-l", "alpha")
    require(result.returncode == 0, result.stderr)
    require("owned by another package" in result.stderr, result.stderr)
    require("beta" not in result.stderr, "owners should require verbosity")

    result = run(root, store, binding_args, "-v", "-l", "alpha")
    require(result.returncode == 0, result.stderr)
    require("resolved owners: beta" in result.stderr, result.stderr)

    (root / "etc/alpha").unlink()
    os.symlink("missing", root / "etc/alpha")
    result = run(root, store, binding_args, "-l", "alpha")
    require(result.returncode == 1, result.stderr)
    require("dangling symlink" in result.stderr, result.stderr)

    result = run(root, store, binding_args, "-d", "ghost")
    require(result.returncode == 2, result.stderr)
    require("selected package is absent" in result.stderr, result.stderr)

    missing_store = temporary_path / "missing-state"
    result = run(root, missing_store, binding_args, "-d", "alpha")
    require(result.returncode == 2, "missing native store must fail")
    require(not missing_store.exists(), "read-only client must not initialize state")

result = subprocess.run(
    [str(PKGCHK), "-d"],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
require(result.returncode == 2, "native state authority must be explicit")
require("--canonical-store is required" in result.stderr, result.stderr)

result = subprocess.run(
    [str(PKGCHK), "--help"],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
require(result.returncode == 0, result.stderr)
require("Audit installed package objects" in result.stdout, result.stdout)
require("canonical generation store" in result.stdout, result.stdout)

result = subprocess.run(
    [str(PKGCHK), "--version"],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
require(result.returncode == 0, result.stderr)
require("pkgchk (libpkgaudit)" in result.stdout, result.stdout)

result = subprocess.run(
    [str(PKGCHK), "-l", "-d"],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
require(result.returncode == 2, "conflicting modes must be usage failure")
