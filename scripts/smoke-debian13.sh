#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
package="$project_root/dist/galeikan_0.1.0~preview1_amd64.deb"
if [[ "$(id -u)" != 0 ]]; then
  printf 'Run this isolated Debian smoke test as root.\n' >&2
  exit 1
fi
for command in debootstrap chroot mount mountpoint umount dpkg-deb; do
  command -v "$command" >/dev/null || {
    printf 'Missing command: %s\n' "$command" >&2
    exit 1
  }
done
if [[ ! -f "$package" ]]; then
  printf 'Missing package: %s\n' "$package" >&2
  exit 1
fi

rootfs="$(mktemp -d /tmp/galeikan-debian13.XXXXXX)"
cleanup() {
  if mountpoint -q "$rootfs/proc"; then
    umount "$rootfs/proc" || return
  fi
  case "$rootfs" in
    /tmp/galeikan-debian13.*) rm -rf -- "$rootfs" ;;
    *) printf 'Refusing to remove unexpected rootfs: %s\n' "$rootfs" >&2 ;;
  esac
}
trap cleanup EXIT

debootstrap --variant=minbase --arch=amd64 trixie "$rootfs" "${GALEIKAN_DEBIAN_MIRROR:-https://deb.debian.org/debian}"
mount -t proc proc "$rootfs/proc"
cp "$package" "$rootfs/tmp/galeikan.deb"
chroot "$rootfs" /usr/bin/dpkg -i /tmp/galeikan.deb
[[ -f "$rootfs/usr/share/icons/hicolor/256x256/mimetypes/text-x-galeikan.png" &&
   -f "$rootfs/usr/share/icons/hicolor/256x256/mimetypes/text-x-galeikan-script.png" &&
   -f "$rootfs/usr/share/galeikan/brand/logo_GaleikanEcosystem.jpg" &&
   -f "$rootfs/usr/share/galeikan/editor/vscode/package.json" ]] || {
  printf 'Installed Galeikan file type or editor assets are missing in Debian 13.\n' >&2
  exit 1
}

example=/usr/share/doc/galeikan/examples
chroot "$rootfs" /usr/bin/galeikan check "$example/hello.gak"
printf 'print 42\n' > "$rootfs/tmp/syntax-smoke.gaks"
chroot "$rootfs" /usr/bin/galeikan check /tmp/syntax-smoke.gaks
[[ "$(chroot "$rootfs" /usr/bin/galeikan run /tmp/syntax-smoke.gaks --engine vm)" == 42 ]]
chroot "$rootfs" /usr/bin/galeikan build /tmp/syntax-smoke.gaks
[[ "$(chroot "$rootfs" /usr/bin/galeikan exec /tmp/syntax-smoke.gakb)" == 42 ]]
hello="$(chroot "$rootfs" /usr/bin/galeikan run "$example/hello.gak" --engine vm)"
[[ "$hello" == $'Hello, Galeikan!\n42' ]] || {
  printf 'Installed CLI example failed in Debian 13.\n' >&2
  exit 1
}
imports="$(chroot "$rootfs" /usr/bin/galeikan run "$example/grouped_imports.gak" --engine vm)"
[[ "$imports" == 4d5a ]] || {
  printf 'Installed module import example failed in Debian 13.\n' >&2
  exit 1
}
splice="$(chroot "$rootfs" /usr/bin/galeikan run "$example/splice.gak" \
  --engine vm --case /tmp/splice-case.json)"
[[ "$splice" == $'4142ff004344\n414344\n41434445\nimpact {'* ]] || {
  printf 'Installed splice example failed in Debian 13.\n' >&2
  exit 1
}
chroot "$rootfs" /usr/bin/galeikan verify-case /tmp/splice-case.json
decision="$(chroot "$rootfs" /usr/bin/galeikan run "$example/decision_chain.gak" --engine vm)"
[[ "$decision" == $'critical\nhigh\nmedium\nlow\n11\n7' ]] || {
  printf 'Installed else-if decision example failed in Debian 13.\n' >&2
  exit 1
}
conditional="$(chroot "$rootfs" /usr/bin/galeikan run "$example/conditional_actions.gak" --engine vm)"
[[ "$conditional" == $'high\n1\n1\n0' ]] || {
  printf 'Installed conditional action example failed in Debian 13.\n' >&2
  exit 1
}
early="$(chroot "$rootfs" /usr/bin/galeikan run "$example/early_return.gak" --engine vm)"
[[ "$early" == $'critical\nreview\nlow\n3\n2\n0' ]] || {
  printf 'Installed early-return example failed in Debian 13.\n' >&2
  exit 1
}
exhaustive="$(chroot "$rootfs" /usr/bin/galeikan run "$example/exhaustive_return.gak" --engine vm)"
[[ "$exhaustive" == $'critical\nreview\nlow\n3\n-1\n0' ]] || {
  printf 'Installed exhaustive-return example failed in Debian 13.\n' >&2
  exit 1
}
integer="$(chroot "$rootfs" /usr/bin/galeikan run "$example/integer_boundaries.gak" --engine vm)"
[[ "$integer" == $'4\nimpact {'* && "$integer" == *'value: 65535 }' ]] || {
  printf 'Installed integer-boundary mutation example failed in Debian 13.\n' >&2
  exit 1
}
hex_output="$(chroot "$rootfs" /usr/bin/galeikan run "$example/hex_view.gak" --engine vm)"
[[ "$hex_output" == '00000000  47 41 4b 00'* && "$hex_output" == *'|ABC|' ]] || {
  printf 'Installed hexdump example failed in Debian 13.\n' >&2
  exit 1
}
profile="$(chroot "$rootfs" /usr/bin/galeikan run "$example/binary_profile.gak" \
  --engine vm --allow-read /usr/bin -- /usr/bin/galeikan)"
[[ "$profile" == $'elf\n64\nlittle\nx86_64\nimpact {'* ]] || {
  printf 'Installed binary profile example failed in Debian 13.\n' >&2
  exit 1
}
chroot "$rootfs" /usr/bin/galeikan run "$example/section_wx.gak" \
  --allow-read /usr/bin --case /tmp/section-wx-case.json -- /usr/bin/galeikan
chroot "$rootfs" /usr/bin/galeikan verify-case /tmp/section-wx-case.json
relro="$(chroot "$rootfs" /usr/bin/galeikan run "$example/relro_audit.gak" \
  --allow-read /usr/bin --case /tmp/relro-case.json -- /usr/bin/true)"
[[ "$relro" == *'signal: "elf.relro_now"'* ]] || {
  printf 'Installed RELRO metadata audit failed in Debian 13.\n' >&2
  exit 1
}
chroot "$rootfs" /usr/bin/galeikan verify-case /tmp/relro-case.json

chroot "$rootfs" /usr/bin/apt-get update -qq
chroot "$rootfs" /usr/bin/env DEBIAN_FRONTEND=noninteractive LANG=C \
  /usr/bin/apt-get install -y -qq python3
pythonpath=/usr/share/galeikan/python
module="$(chroot "$rootfs" /usr/bin/env PYTHONDONTWRITEBYTECODE=1 "PYTHONPATH=$pythonpath" /usr/bin/python3 \
  "$example/python_module_view.py" /usr/bin/galeikan)"
session="$(chroot "$rootfs" /usr/bin/env PYTHONDONTWRITEBYTECODE=1 "PYTHONPATH=$pythonpath" /usr/bin/python3 \
  "$example/python_persistent_session.py" /usr/bin/galeikan)"
state="$(chroot "$rootfs" /usr/bin/env PYTHONDONTWRITEBYTECODE=1 /usr/bin/galeikan run "$example/python_state.gak" \
  --allow-python /usr/bin/python3)"
[[ "$module" == $'42\nb\x27GAK\x27' && "$session" == "$module" && "$state" == $'1\n2\n2' ]] || {
  printf 'Installed Python bridge examples failed in Debian 13.\n' >&2
  exit 1
}
interop="$(chroot "$rootfs" /usr/bin/galeikan run "$example/interop/main.gak" \
  --engine vm --allow-python /usr/bin/python3)"
caller="$(chroot "$rootfs" /usr/bin/env PYTHONDONTWRITEBYTECODE=1 "PYTHONPATH=$pythonpath" /usr/bin/python3 \
  "$example/interop/caller.py")"
[[ "$interop" == 44 && "$caller" == 44 ]] || {
  printf 'Installed bidirectional interop example failed in Debian 13.\n' >&2
  exit 1
}

chroot "$rootfs" /usr/bin/dpkg -r galeikan
if [[ -e "$rootfs/usr/bin/galeikan" || -e "$rootfs/usr/share/galeikan" ]]; then
  printf 'Debian package removal left installed files behind.\n' >&2
  exit 1
fi
printf 'Debian 13 install, CLI, modules, binary profile, Python bridge and removal passed.\n'
