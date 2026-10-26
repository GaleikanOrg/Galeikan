#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
source_image="logo_GaleikanEcosystem.jpg"
windows_assets="packaging/windows/assets"
debian_assets="packaging/debian"

if ! command -v magick >/dev/null 2>&1; then
  printf 'ImageMagick is required to regenerate Galeikan brand assets.\n' >&2
  exit 1
fi
if [[ ! -f "$source_image" ]]; then
  printf 'Missing Ecosystem artwork: %s\n' "$source_image" >&2
  exit 1
fi

# Keep the exact source JPEG in the packages. These derived formats are only
# for installer surfaces and operating-system file associations.
icon_crop='900x900+177+30'
wordmark_crop='1120x210+67+942'
magick "$source_image" -crop "$icon_crop" +repage -resize 256x256 \
  "$debian_assets/text-x-galeikan.png"
cp "$debian_assets/text-x-galeikan.png" "$debian_assets/text-x-galeikan-script.png"

magick "$source_image" -crop "$icon_crop" +repage \
  \( -clone 0 -resize 256x256 \) \
  \( -clone 0 -resize 64x64 \) \
  \( -clone 0 -resize 48x48 \) \
  \( -clone 0 -resize 32x32 \) \
  \( -clone 0 -resize 16x16 \) \
  -delete 0 "$windows_assets/galeikan.ico"

magick -size 150x57 xc:black \
  \( "$source_image" -crop "$wordmark_crop" +repage -resize 145x27 \) \
  -gravity center -composite BMP3:"$windows_assets/header.bmp"

magick -size 164x314 xc:black \
  \( "$source_image" -crop "$icon_crop" +repage -resize 154x154 \) \
  -geometry +5+27 -composite \
  \( "$source_image" -crop "$wordmark_crop" +repage -resize 158x30 \) \
  -geometry +3+218 -composite BMP3:"$windows_assets/welcome.bmp"
