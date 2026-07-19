#!/usr/bin/env python3
import os
import pathlib
import subprocess
import sys
import tempfile

PKGCHK = pathlib.Path(sys.argv[1])


def write_db(root: pathlib.Path, records):
    directory = root / "var/lib/pkg"
    directory.mkdir(parents=True)
    with (directory / "db").open("w", encoding="utf-8", newline="\n") as out:
        for name, version, paths in records:
            out.write(name + "\n" + version + "\n")
            for path in paths:
                out.write(path + "\n")
            out.write("\n")


def run(root: pathlib.Path, *args):
    return subprocess.run(
        [str(PKGCHK), "-r", str(root), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def require(condition, message):
    if not condition:
        raise AssertionError(message)


with tempfile.TemporaryDirectory(prefix="libpkgaudit-cli.") as temporary:
    root = pathlib.Path(temporary)
    (root / "etc").mkdir()
    (root / "etc/alpha").write_text("ok\n", encoding="utf-8")
    (root / "usr/lib").mkdir(parents=True)
    (root / "usr/lib/target").write_text("target\n", encoding="utf-8")
    write_db(root, [
        ("alpha", "1.0-1", ["etc/alpha", "usr/lib/"]),
        ("beta", "1.0-1", ["usr/lib/target"]),
    ])

    result = run(root, "-d", "alpha")
    require(result.returncode == 0, result.stderr)

    (root / "etc/alpha").unlink()
    result = run(root, "-d", "alpha")
    require(result.returncode == 1, result.stderr)
    require("missing object /etc/alpha" in result.stderr, result.stderr)

    (root / "etc/alpha").mkdir()
    result = run(root, "-d", "alpha")
    require(result.returncode == 1, result.stderr)
    require("object class mismatch" in result.stderr, result.stderr)
    (root / "etc/alpha").rmdir()

    os.symlink("/usr/lib/target", root / "etc/alpha")
    result = run(root, "-l", "alpha")
    require(result.returncode == 0, result.stderr)
    require("owned by another package" in result.stderr, result.stderr)
    require("beta" not in result.stderr, "owners should require verbosity")

    result = run(root, "-v", "-l", "alpha")
    require(result.returncode == 0, result.stderr)
    require("resolved owners: beta" in result.stderr, result.stderr)

    (root / "etc/alpha").unlink()
    os.symlink("missing", root / "etc/alpha")
    result = run(root, "-l", "alpha")
    require(result.returncode == 1, result.stderr)
    require("dangling symlink" in result.stderr, result.stderr)

    result = run(root, "-d", "ghost")
    require(result.returncode == 2, result.stderr)
    require("selected package is absent" in result.stderr, result.stderr)

result = subprocess.run(
    [str(PKGCHK), "-d"], text=True, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, check=False)
require(result.returncode == 2, "missing default database must be operational failure")

result = subprocess.run(
    [str(PKGCHK), "--help"], text=True, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, check=False)
require(result.returncode == 0, result.stderr)
require("Exit status" not in result.stderr, result.stderr)
require("Audit installed package objects" in result.stdout, result.stdout)

result = subprocess.run(
    [str(PKGCHK), "--version"], text=True, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, check=False)
require(result.returncode == 0, result.stderr)
require("pkgchk (libpkgaudit)" in result.stdout, result.stdout)

result = subprocess.run(
    [str(PKGCHK), "-l", "-d"], text=True, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, check=False)
require(result.returncode == 2, "conflicting modes must be usage failure")
