#!/usr/bin/env python3
import sys
import re
from pathlib import Path

def bump_file(path, new_version, pattern):
    file_path = Path(path)
    if not file_path.exists():
        print(f"❌ Error: {path} not found.")
        sys.exit(1)
        
    content = file_path.read_text()
    
    # Regex explanation:
    # ^: Start of line
    # \s*: Optional whitespace
    # version: The key
    # \s*=\s*: Equals sign with optional whitespace
    # "[^"]+": The old version inside quotes
    # (flags=re.MULTILINE to handle file line by line)
    new_content = re.sub(
        pattern, 
        f'version = "{new_version}"', 
        content, 
        count=1, # Only replace the first occurrence (usually the package version)
        flags=re.MULTILINE
    )
    
    if content == new_content:
        print(f"⚠️  Warning: Version in {path} was not updated (maybe it's already {new_version}?)")
    else:
        file_path.write_text(new_content)
        print(f"✅ Updated {path} to {new_version}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/bump.py <new_version>")
        sys.exit(1)

    new_version = sys.argv[1]
    
    # Verify format (x.y.z)
    if not re.match(r'^\d+\.\d+\.\d+$', new_version):
        print("❌ Error: Version must be in format X.Y.Z")
        sys.exit(1)

    print(f"🚀 Bumping versions to {new_version}...")

    # 1. Update Cargo.toml
    # Cargo.toml uses [package] -> version = "x.y.z"
    bump_file("Cargo.toml", new_version, r'^version\s*=\s*"[^"]+"')

    # 2. Update pyproject.toml
    # pyproject.toml uses [project] -> version = "x.y.z"
    bump_file("pyproject.toml", new_version, r'^version\s*=\s*"[^"]+"')

if __name__ == "__main__":
    main()
