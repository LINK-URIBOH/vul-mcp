import argparse
from pathlib import Path
import sys
import tarfile

from vulintel.config import settings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["backup", "restore"])
    args = parser.parse_args()
    root = settings().data_dir
    if args.mode == "backup":
        with tarfile.open(fileobj=sys.stdout.buffer, mode="w|gz") as archive:
            if (root / "reports").exists():
                archive.add(root / "reports", arcname="reports")
    else:
        root.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=sys.stdin.buffer, mode="r|gz") as archive:
            for member in archive:
                path = Path(member.name)
                if not path.parts or path.parts[0] != "reports" or path.is_absolute() or ".." in path.parts:
                    raise ValueError("Invalid report archive path")
                if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                    raise ValueError("Archive links and special files are refused")
                archive.extract(member, path=root, filter="data")


if __name__ == "__main__":
    main()
