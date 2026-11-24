#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
architecture="$(dpkg --print-architecture)"
if [[ "$architecture" != amd64 ]]; then
  printf 'Debian packaging supports amd64 only (got %s).\n' "$architecture" >&2
  exit 1
fi
version="$(sed -n '/^\[package\]/,/^\[/{s/^version = "\([^"]*\)"/\1/p;}' Cargo.toml | head -n 1)"
if [[ -z "$version" ]]; then
  printf 'Could not read package version from Cargo.toml.\n' >&2
  exit 1
fi
release_channel="$(cat packaging/release-channel.txt)"
if [[ ! "$release_channel" =~ ^(stable|preview[1-9][0-9]*)$ ]]; then
  printf 'Invalid Galeikan release channel.\n' >&2
  exit 1
fi
debian_version="$version"
artifact_version="$version"
description='Galeikan research language (Debian 13)'
if [[ "$release_channel" != stable ]]; then
  debian_version+="~$release_channel"
  artifact_version+=".$release_channel"
  description='Galeikan research language (Debian 13 development preview)'
fi
linux_target_dir="${GALEIKAN_LINUX_TARGET_DIR:-${CARGO_TARGET_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/galeikan-script-target}}"
if [[ "${1:-}" != --skip-cargo-build ]]; then
  CARGO_TARGET_DIR="$linux_target_dir" cargo build --release
fi
binary="$linux_target_dir/release/galeikan"
decoder="$linux_target_dir/release/libgaleikan_asm.so"
if [[ ! -x "$binary" ]]; then
  printf 'Missing Linux release binary: %s\n' "$binary" >&2
  exit 1
fi
if [[ ! -f "$decoder" ]]; then
  printf 'Missing Linux decoder library: %s\n' "$decoder" >&2
  exit 1
fi

staging="$(mktemp -d)"
trap 'rm -rf -- "$staging"' EXIT
install -Dm755 "$binary" "$staging/usr/bin/galeikan"
install -Dm755 "$decoder" "$staging/usr/lib/galeikan/libgaleikan_asm.so"
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
for editor_asset in \
  package.json README.md icon.png language-configuration.json \
  syntaxes/galeikan.tmLanguage.json; do
  install -Dm644 "editors/vscode/galeikan/$editor_asset" \
    "$staging/usr/share/galeikan/editor/vscode/galeikan-language/$editor_asset"
done
for editor_asset in package.json README.md icon.png themes/galeikan-noir-color-theme.json; do
  install -Dm644 "editors/vscode/galeikan-eclipse/$editor_asset" \
    "$staging/usr/share/galeikan/editor/vscode/galeikan-eclipse/$editor_asset"
done

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

glibc_version="$(objdump -T "$binary" "$decoder" | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/^GLIBC_//' | sort -Vu | tail -n 1)"
if [[ -z "$glibc_version" ]]; then
  printf 'Could not determine required glibc version.\n' >&2
  exit 1
fi
if dpkg --compare-versions "$glibc_version" gt 2.41; then
  printf 'Linux binary requires glibc %s, which exceeds the Debian 13 baseline (2.41).\n' "$glibc_version" >&2
  exit 1
fi

output_dir="${GALEIKAN_DEB_OUTPUT_DIR:-$project_root/dist}"
mkdir -p "$staging/DEBIAN" "$output_dir"
cat > "$staging/DEBIAN/control" <<EOF
Package: galeikan
Version: ${debian_version}
Section: devel
Priority: optional
Architecture: amd64
Maintainer: Galeikan Project
Depends: libc6 (>= ${glibc_version}), libgcc-s1, gcc, libc6-dev
Description: ${description}
 Galeikan provides a research-oriented scripting language with explicit
 effects, bounded binary inspection, local modules and optional Python interop.
 The native compiler supports a limited x86-64 subset of the language.
EOF

package="$output_dir/galeikan_${artifact_version}_${architecture}.deb"
dpkg-deb --root-owner-group --build "$staging" "$package"
printf '%s\n' "$package"
