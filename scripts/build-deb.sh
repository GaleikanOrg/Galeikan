#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
architecture="$(dpkg --print-architecture)"
if [[ "$architecture" != amd64 ]]; then
  printf 'This preview packaging script supports amd64 only (got %s).\n' "$architecture" >&2
  exit 1
fi
version="$(sed -n '/^\[package\]/,/^\[/{s/^version = "\([^"]*\)"/\1/p;}' Cargo.toml | head -n 1)"
if [[ -z "$version" ]]; then
  printf 'Could not read package version from Cargo.toml.\n' >&2
  exit 1
fi
linux_target_dir="${GALEIKAN_LINUX_TARGET_DIR:-${CARGO_TARGET_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/galeikan-script-target}}"
if [[ "${1:-}" != --skip-cargo-build ]]; then
  CARGO_TARGET_DIR="$linux_target_dir" cargo build --release
fi
binary="$linux_target_dir/release/galeikan"
if [[ ! -x "$binary" ]]; then
  printf 'Missing Linux release binary: %s\n' "$binary" >&2
  exit 1
fi

staging="$(mktemp -d)"
trap 'rm -rf -- "$staging"' EXIT
install -Dm755 "$binary" "$staging/usr/bin/galeikan"
install -Dm644 packaging/README.md "$staging/usr/share/doc/galeikan/README.md"
install -Dm644 python/pyproject.toml "$staging/usr/share/galeikan/python/pyproject.toml"
install -Dm644 python/galeikan_bridge/__init__.py "$staging/usr/share/galeikan/python/galeikan_bridge/__init__.py"
install -Dm644 python/galeikan_bridge/_runner.py "$staging/usr/share/galeikan/python/galeikan_bridge/_runner.py"
mkdir -p "$staging/usr/share/doc/galeikan/docs" "$staging/usr/share/doc/galeikan/examples"
cp packaging/docs/*.md "$staging/usr/share/doc/galeikan/docs/"
while IFS= read -r -d '' example; do
  target="$staging/usr/share/doc/galeikan/examples/${example#examples/}"
  install -Dm644 "$example" "$target"
done < <(find examples -type f ! -path '*/__pycache__/*' ! -name '*.pyc' -print0)
find "$staging/usr/share/doc/galeikan/docs" -type f -exec chmod 644 {} +
install -Dm644 packaging/debian/galeikan.xml "$staging/usr/share/mime/packages/galeikan.xml"
install -Dm644 logo_GaleikanEcosystem.jpg "$staging/usr/share/galeikan/brand/logo_GaleikanEcosystem.jpg"
install -Dm644 packaging/debian/text-x-galeikan.png "$staging/usr/share/icons/hicolor/256x256/mimetypes/text-x-galeikan.png"
install -Dm644 packaging/debian/text-x-galeikan-script.png "$staging/usr/share/icons/hicolor/256x256/mimetypes/text-x-galeikan-script.png"
while IFS= read -r -d '' editor_file; do
  target="$staging/usr/share/galeikan/editor/vscode/${editor_file#editors/vscode/galeikan/}"
  install -Dm644 "$editor_file" "$target"
done < <(find editors/vscode/galeikan -type f -print0)

mkdir -p "$staging/DEBIAN"
cat > "$staging/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v update-mime-database >/dev/null 2>&1; then
  update-mime-database /usr/share/mime
fi
EOF
cat > "$staging/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if command -v update-mime-database >/dev/null 2>&1; then
  update-mime-database /usr/share/mime
fi
EOF
chmod 755 "$staging/DEBIAN/postinst" "$staging/DEBIAN/postrm"

glibc_version="$(objdump -T "$binary" | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/^GLIBC_//' | sort -Vu | tail -n 1)"
if [[ -z "$glibc_version" ]]; then
  printf 'Could not determine required glibc version.\n' >&2
  exit 1
fi
if dpkg --compare-versions "$glibc_version" gt 2.41; then
  printf 'Linux binary requires glibc %s, which exceeds the Debian 13 baseline (2.41).\n' "$glibc_version" >&2
  exit 1
fi

mkdir -p "$staging/DEBIAN" "$project_root/dist"
cat > "$staging/DEBIAN/control" <<EOF
Package: galeikan
Version: ${version}~preview2
Section: devel
Priority: optional
Architecture: amd64
Maintainer: Galeikan Project
Depends: libc6 (>= ${glibc_version}), libgcc-s1
Description: Galeikan research language (Debian 13 development preview)
 Galeikan provides a research-oriented scripting language with explicit
 effects, bounded binary inspection, local modules and optional Python interop.
 The native compiler supports a limited x86-64 subset of the language.
EOF

package="$project_root/dist/galeikan_${version}~preview2_${architecture}.deb"
dpkg-deb --root-owner-group --build "$staging" "$package"
printf '%s\n' "$package"
