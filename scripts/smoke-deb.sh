#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
package="$project_root/dist/galeikan_0.1.0~preview1_amd64.deb"
if [[ ! -f "$package" ]]; then
  printf 'Missing package: %s\n' "$package" >&2
  exit 1
fi
[[ "$(dpkg-deb --field "$package" Package)" == galeikan ]] || {
  printf 'Debian product name is not Galeikan.\n' >&2
  exit 1
}
staging="$(mktemp -d)"
trap 'rm -rf -- "$staging"' EXIT
dpkg-deb --extract "$package" "$staging"
binary="$staging/usr/bin/galeikan"
example="$staging/usr/share/doc/galeikan/examples/hello.gak"
test -f "$staging/usr/share/icons/hicolor/256x256/mimetypes/text-x-galeikan.png"
test -f "$staging/usr/share/icons/hicolor/256x256/mimetypes/text-x-galeikan-script.png"
cmp "$project_root/logo_GaleikanEcosystem.jpg" "$staging/usr/share/galeikan/brand/logo_GaleikanEcosystem.jpg"
test -f "$staging/usr/share/galeikan/editor/vscode/package.json"
for asset in language-configuration.json syntaxes/galeikan.tmLanguage.json themes/galeikan-noir-color-theme.json; do
  cmp "$project_root/editors/vscode/galeikan/$asset" "$staging/usr/share/galeikan/editor/vscode/$asset"
done
for asset in pyproject.toml galeikan_bridge/__init__.py galeikan_bridge/_runner.py; do
  cmp "$project_root/python/$asset" "$staging/usr/share/galeikan/python/$asset"
done
update-mime-database "$staging/usr/share/mime"
grep -Fq 'text/x-galeikan:*.gak' "$staging/usr/share/mime/globs2"
grep -Fq 'text/x-galeikan-script:*.gaks' "$staging/usr/share/mime/globs2"
cmp "$project_root/packaging/README.md" "$staging/usr/share/doc/galeikan/README.md"
cmp "$project_root/packaging/docs/quickstart.md" "$staging/usr/share/doc/galeikan/docs/quickstart.md"
[[ "$(find "$staging/usr/share/doc/galeikan/docs" -type f | wc -l)" -eq 1 ]]
"$binary" check "$example"
printf 'print 42\n' > "$staging/syntax-smoke.gaks"
"$binary" check "$staging/syntax-smoke.gaks"
[[ "$("$binary" run "$staging/syntax-smoke.gaks" --engine vm)" == 42 ]]
"$binary" build "$staging/syntax-smoke.gaks"
[[ "$("$binary" exec "$staging/syntax-smoke.gakb")" == 42 ]]
"$binary" compile "$staging/syntax-smoke.gaks"
[[ "$("$staging/syntax-smoke.gaks.native")" == 42 ]]
cat > "$staging/native-udp-smoke.gak" <<'GAK'
requires { net.connect }
from std.net import datagram
from std.bytes import from_hex, repeat
print datagram("127.0.0.1", 9, repeat(from_hex("01"), 65508), 1, 100)
GAK
"$binary" compile "$staging/native-udp-smoke.gak"
if "$staging/native-udp-smoke.gak.native" --allow-connect 127.0.0.1:9 \
     > "$staging/native-udp.out" 2> "$staging/native-udp.err" ||
   ! grep -Fq 'request exceeds 65507 bytes' "$staging/native-udp.err"; then
  printf 'Installed native UDP request limit failed.\n' >&2
  exit 1
fi
printf 'GAK' > "$staging/native-read.bin"
cat > "$staging/native-read-smoke.gak" <<'EOF'
requires { file.read }
from std.binary import analyze, size
print size(analyze("native-read.bin", 16))
EOF
"$binary" compile "$staging/native-read-smoke.gak"
[[ "$("$staging/native-read-smoke.gak.native" --allow-read "$staging")" == 3 ]]
if "$staging/native-read-smoke.gak.native" > "$staging/native-read-denied.out" 2> "$staging/native-read-denied.err" ||
   ! grep -Fq 'file access not allowed' "$staging/native-read-denied.err"; then
  printf 'Installed native file-read permission check failed.\n' >&2
  exit 1
fi
printf 'struct Header { marker: str, offset: i64 }\nlet header = Header("MZ", 4)\nprint header.marker\nprint header.offset\n' > "$staging/struct-smoke.gak"
[[ "$("$binary" run "$staging/struct-smoke.gak" --engine vm)" == $'MZ\n4' ]]
"$binary" compile "$staging/struct-smoke.gak"
[[ "$("$staging/struct-smoke.gak.native")" == $'MZ\n4' ]]
cat > "$staging/loop-smoke.gaks" <<'EOF'
var count = 0
while count < 5 {
    count = count + 1
    if count == 2 {
        continue
    }
    if count == 4 {
        break
    }
    print count
}
EOF
[[ "$("$binary" run "$staging/loop-smoke.gaks" --engine vm)" == $'1\n3' ]]
"$binary" compile "$staging/loop-smoke.gaks"
[[ "$("$staging/loop-smoke.gaks.native")" == $'1\n3' ]]
cat > "$staging/class-smoke.gaks" <<'EOF'
class Pair {
    left: i64
    right: i64
    fn total() -> i64 = self.left + self.right
}
print Pair(2, 3).total()
EOF
[[ "$("$binary" run "$staging/class-smoke.gaks" --engine vm)" == 5 ]]
"$binary" compile "$staging/class-smoke.gaks"
[[ "$("$staging/class-smoke.gaks.native")" == 5 ]]
printf 'print 0xffffffffffffffff >>> 63\nprint (0xf0 & 0x3c) | 0x80\n' > "$staging/bits-smoke.gak"
[[ "$("$binary" run "$staging/bits-smoke.gak" --engine vm)" == $'1\n176' ]]
"$binary" compile "$staging/bits-smoke.gak"
[[ "$("$staging/bits-smoke.gak.native")" == $'1\n176' ]]
printf 'print match 0x5a { 0x4d => 0, 0x5a => 1, _ => 2 }\n' > "$staging/match-smoke.gak"
[[ "$("$binary" run "$staging/match-smoke.gak" --engine vm)" == 1 ]]
"$binary" compile "$staging/match-smoke.gak"
[[ "$("$staging/match-smoke.gak.native")" == 1 ]]
"$binary" check "$staging/usr/share/doc/galeikan/examples/interop/main.gak"
grouped_output="$("$binary" run "$staging/usr/share/doc/galeikan/examples/grouped_imports.gak")"
if [[ "$grouped_output" != '4d5a' ]]; then
  printf 'Installed grouped import example failed.\n' >&2
  exit 1
fi
splice_output="$("$binary" run "$staging/usr/share/doc/galeikan/examples/splice.gak" --engine vm --case "$staging/splice-case.json")"
if [[ "$splice_output" != $'4142ff004344\n414344\n41434445\nimpact {'* ]]; then
  printf 'Installed splice example failed.\n' >&2
  exit 1
fi
"$binary" verify-case "$staging/splice-case.json"
decision_output="$("$binary" run "$staging/usr/share/doc/galeikan/examples/decision_chain.gak" --engine vm)"
if [[ "$decision_output" != $'critical\nhigh\nmedium\nlow\n11\n7' ]]; then
  printf 'Installed else-if decision example failed.\n' >&2
  exit 1
fi
conditional_output="$("$binary" run "$staging/usr/share/doc/galeikan/examples/conditional_actions.gak" --engine vm)"
if [[ "$conditional_output" != $'high\n1\n1\n0' ]]; then
  printf 'Installed conditional action example failed.\n' >&2
  exit 1
fi
cp "$staging/usr/share/doc/galeikan/examples/conditional_actions.gak" "$staging/conditional-actions.gak"
"$binary" compile "$staging/conditional-actions.gak"
conditional_native="$("$staging/conditional-actions.gak.native")"
if [[ "$conditional_native" != $'high\n1\n1\n0' ]]; then
  printf 'Installed conditional action native execution failed.\n' >&2
  exit 1
fi
early_example="$staging/usr/share/doc/galeikan/examples/early_return.gak"
early_output="$("$binary" run "$early_example" --engine vm)"
if [[ "$early_output" != $'critical\nreview\nlow\n3\n2\n0' ]]; then
  printf 'Installed early-return example failed.\n' >&2
  exit 1
fi
cp "$early_example" "$staging/early-return.gak"
"$binary" compile "$staging/early-return.gak"
early_native="$("$staging/early-return.gak.native")"
if [[ "$early_native" != "$early_output" ]]; then
  printf 'Installed early-return native execution failed.\n' >&2
  exit 1
fi
integer_output="$("$binary" run "$staging/usr/share/doc/galeikan/examples/integer_boundaries.gak" --engine vm)"
if [[ "$integer_output" != $'4\nimpact {'* || "$integer_output" != *'value: 65535 }' ]]; then
  printf 'Installed integer-boundary mutation example failed.\n' >&2
  exit 1
fi
hex_output="$("$binary" run "$staging/usr/share/doc/galeikan/examples/hex_view.gak" --engine vm)"
if [[ "$hex_output" != '00000000  47 41 4b 00'* || "$hex_output" != *'|ABC|' ]]; then
  printf 'Installed hexdump example failed.\n' >&2
  exit 1
fi
exhaustive_example="$staging/usr/share/doc/galeikan/examples/exhaustive_return.gak"
exhaustive_output="$("$binary" run "$exhaustive_example" --engine vm)"
if [[ "$exhaustive_output" != $'critical\nreview\nlow\n3\n-1\n0' ]]; then
  printf 'Installed exhaustive-return example failed.\n' >&2
  exit 1
fi
cp "$exhaustive_example" "$staging/exhaustive-return.gak"
"$binary" compile "$staging/exhaustive-return.gak"
exhaustive_native="$("$staging/exhaustive-return.gak.native")"
if [[ "$exhaustive_native" != "$exhaustive_output" ]]; then
  printf 'Installed exhaustive-return native execution failed.\n' >&2
  exit 1
fi
result_output="$("$binary" run "$staging/usr/share/doc/galeikan/examples/result_explicit.gak" --engine vm)"
if [[ "$result_output" != $'marker needs at least three bytes\nimpact {'* ]]; then
  printf 'Installed Result<T> example failed.\n' >&2
  exit 1
fi
package_output="$("$binary" run "$staging/usr/share/doc/galeikan/examples/package_demo/src/main.gak" --engine vm)"
if [[ "$package_output" != $'MZ marker\nimpact {'* ]]; then
  printf 'Installed versioned transitive package example failed.\n' >&2
  exit 1
fi
printf 'from std.binary import absent\nprint 1\n' > "$staging/missing-import.gak"
if "$binary" check "$staging/missing-import.gak" 2> "$staging/missing-import.err" ||
   ! grep -q 'unknown imported symbol absent' "$staging/missing-import.err"; then
  printf 'Installed CLI did not reject a missing from-import.\n' >&2
  exit 1
fi
"$binary" check "$staging/usr/share/doc/galeikan/examples/delay_imports.gak"
module_output="$(PYTHONPATH="$staging/usr/share/galeikan/python" python3 "$staging/usr/share/doc/galeikan/examples/python_module_view.py" "$binary")"
if [[ "$module_output" != $'42\nb\x27GAK\x27' ]]; then
  printf 'Installed Python module view failed.\n' >&2
  exit 1
fi
session_output="$(PYTHONPATH="$staging/usr/share/galeikan/python" python3 "$staging/usr/share/doc/galeikan/examples/python_persistent_session.py" "$binary")"
if [[ "$session_output" != $'42\nb\x27GAK\x27' ]]; then
  printf 'Installed persistent Galeikan session failed.\n' >&2
  exit 1
fi
state_output="$("$binary" run "$staging/usr/share/doc/galeikan/examples/python_state.gak" --allow-python "$(command -v python3)")"
if [[ "$state_output" != $'1\n2\n2' ]]; then
  printf 'Installed persistent Python module example failed.\n' >&2
  exit 1
fi
interop_output="$("$binary" run "$staging/usr/share/doc/galeikan/examples/interop/main.gak" --engine vm --allow-python "$(command -v python3)")"
if [[ "$interop_output" != '44' ]]; then
  printf 'Installed Galeikan-to-Python interop example failed.\n' >&2
  exit 1
fi
caller_output="$(PATH="$(dirname "$binary"):$PATH" PYTHONPATH="$staging/usr/share/galeikan/python" python3 "$staging/usr/share/doc/galeikan/examples/interop/caller.py")"
if [[ "$caller_output" != '44' ]]; then
  printf 'Installed Python-to-Galeikan interop example failed.\n' >&2
  exit 1
fi
"$binary" check "$staging/usr/share/doc/galeikan/examples/udp_probe.gak"
"$binary" check "$staging/usr/share/doc/galeikan/examples/http_fetch.gak"
"$binary" check "$staging/usr/share/doc/galeikan/examples/http_request.gak"
"$binary" check "$staging/usr/share/doc/galeikan/examples/http_module/main.gak"
"$binary" check "$staging/usr/share/doc/galeikan/examples/process_snapshot.gak"
"$binary" check "$staging/usr/share/doc/galeikan/examples/process_regions.gak"
"$binary" check "$staging/usr/share/doc/galeikan/examples/process_images.gak"
profile_example="$staging/usr/share/doc/galeikan/examples/binary_profile.gak"
"$binary" check "$profile_example"
profile_output="$("$binary" run "$profile_example" --allow-read /usr/bin -- /usr/bin/true)"
if [[ "$profile_output" != $'elf\n64\nlittle\nx86_64\nimpact {'* ]]; then
  printf 'Installed binary profile example failed.\n' >&2
  exit 1
fi
modules_example="$staging/usr/share/doc/galeikan/examples/process_modules.gak"
"$binary" check "$modules_example"
modules_output="$("$binary" run "$modules_example" --allow-process "$$" -- "$$")"
modules_count="${modules_output%%$'\n'*}"
if [[ "$modules_count" -le 0 ]]; then
  printf 'Installed process.modules example failed.\n' >&2
  exit 1
fi
printf 'requires { process.inspect }\nfrom std.process import images, at, start, locate, offset, address\nlet maps = images(%s)\nlet region = at(maps, 0)\nlet base = start(region)\nprint address(locate(maps, base), offset(region, base)) == base\n' "$$" > "$staging/process-address-smoke.gak"
[[ "$("$binary" run "$staging/process-address-smoke.gak" --allow-process "$$")" == true ]]
signals_example="$staging/usr/share/doc/galeikan/examples/hardening_signals.gak"
signals_output="$("$binary" run "$signals_example" --allow-read /usr/bin -- /usr/bin/true)"
if [[ "$signals_output" != *$'pe.dynamic_base\nnot_applicable'* ||
      "$signals_output" != *$'elf.gnu_relro\n'* ||
      "$signals_output" != *$'elf.bind_now\n'* ||
      "$signals_output" != *$'elf.relro_now\n'* ]]; then
  printf 'Installed CLI format signal inspection failed.\n' >&2
  exit 1
fi
cat > "$staging/native-format-smoke.gak" <<'GAK'
requires { file.read }
from std.binary import analyze
from std.formats import probe, kind, bits, signal
from std.cli import arg
let report: Format = probe(analyze(arg(0), 67108864))
print kind(report)
print bits(report)
print signal(report, "elf.gnu_stack_nx")
GAK
"$binary" compile "$staging/native-format-smoke.gak"
native_format_output="$("$staging/native-format-smoke.gak.native" --allow-read /usr/bin -- /usr/bin/true)"
if [[ "$native_format_output" != $'elf\n64\npresent' ]]; then
  printf 'Installed native ELF format inspection failed: %s\n' "$native_format_output" >&2
  exit 1
fi
wx_example="$staging/usr/share/doc/galeikan/examples/section_wx.gak"
"$binary" run "$wx_example" --allow-read /usr/bin --case "$staging/section-wx-case.json" -- /usr/bin/true
"$binary" verify-case "$staging/section-wx-case.json"
python3 - "$staging/section-wx-case.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    finding = json.load(stream)["events"][-1]["value"]
assert finding["kind"] == "signal"
assert finding["signal"] == "elf.load_rwx"
PY
signal_audit="$staging/usr/share/doc/galeikan/examples/hardening_audit.gak"
"$binary" run "$signal_audit" --allow-read /usr/bin --case "$staging/signal-case.json" -- /usr/bin/true
"$binary" verify-case "$staging/signal-case.json"
python3 - "$staging/signal-case.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    finding = json.load(stream)["events"][0]["value"]
assert finding["kind"] == "signal"
assert finding["signal"] == "elf.gnu_stack_nx"
PY
relro_audit="$staging/usr/share/doc/galeikan/examples/relro_audit.gak"
"$binary" run "$relro_audit" --allow-read /usr/bin --case "$staging/relro-case.json" -- /usr/bin/true
"$binary" verify-case "$staging/relro-case.json"
python3 - "$staging/relro-case.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    finding = json.load(stream)["events"][0]["value"]
assert finding["kind"] == "signal"
assert finding["signal"] == "elf.relro_now"
PY
audit_example="$staging/usr/share/doc/galeikan/examples/audit_hunt.gak"
"$binary" check "$audit_example"
printf '\x4d\x5a\x00\x4d\x5a' > "$staging/audit-sample.bin"
"$binary" run "$audit_example" --allow-read "$staging" --case "$staging/audit-case.json" -- "$staging/audit-sample.bin"
"$binary" verify-case "$staging/audit-case.json"
python3 - "$staging/audit-case.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    finding = json.load(stream)["events"][0]["value"]
assert finding["kind"] == "pattern"
assert finding["count"] == 2
PY
packed_example="$staging/usr/share/doc/galeikan/examples/packed_fields.gak"
"$binary" check "$packed_example"
packed_output="$("$binary" run "$packed_example")"
if [[ "$packed_output" != $'123478563412\n4660\n305419896' ]]; then
  printf 'Installed bytes.pack roundtrip failed: %s\n' "$packed_output" >&2
  exit 1
fi
range_example="$staging/usr/share/doc/galeikan/examples/native_range.gak"
"$binary" check "$range_example"
cp "$range_example" "$staging/native-range.gak"
"$binary" compile "$staging/native-range.gak"
range_output="$("$staging/native-range.gak.native")"
if [[ "$range_output" != 6 ]]; then
  printf 'Installed native range execution failed: %s\n' "$range_output" >&2
  exit 1
fi
cat > "$staging/native-python-helper.py" <<'PY'
def double(values):
    return [value * 2 for value in values]
PY
cat > "$staging/native-python-smoke.gak" <<'GAK'
requires { python.exec }
import "py:native-python-helper.py" as helper
from std.text import length, slice
fn double(value: i64) -> i64 = value * 2
let answers: List<i64> = helper.double([20, 21])
print answers[0]
print answers[1]
print "Galeikan" + "Script"
print length("Galeikan")
print slice("Galeikan", 1, 2) == "al"
GAK
"$binary" compile "$staging/native-python-smoke.gak"
python_output="$("$staging/native-python-smoke.gak.native" --allow-python "$(command -v python3)")"
if [[ "$python_output" != $'40\n42\nGaleikanScript\n8\ntrue' ]]; then
  printf 'Installed native Python bridge failed: %s\n' "$python_output" >&2
  exit 1
fi
reverse_output="$(PYTHONPATH="$staging/usr/share/galeikan/python" python3 -c 'from galeikan_bridge import Galeikan; import sys; print(Galeikan(sys.argv[1]).module(sys.argv[2], allow_python=sys.argv[3]).double(21))' "$binary" "$staging/native-python-smoke.gak.native" "$(command -v python3)")"
if [[ "$reverse_output" != 42 ]]; then
  printf 'Installed Python-to-native Galeikan bridge failed: %s\n' "$reverse_output" >&2
  exit 1
fi
cat > "$staging/native-process-smoke.gak" <<'GAK'
requires { process.inspect }
import std.process
from std.result import is_error
from std.list import count
fn checked() -> Result<Source> {
    let source: Source = process.snapshot(process.self_pid(), 1, 4)
    return source
}
print process.self_pid()
print is_error(checked())
print count(process.modules(process.self_pid())) > 0
print process.parent_pid(process.self_pid()) > 0
print count(process.children(process.self_pid())) == 0
GAK
"$binary" compile "$staging/native-process-smoke.gak"
process_output="$("$staging/native-process-smoke.gak.native" --allow-process self)"
process_pid="${process_output%%$'\n'*}"
if [[ ! "$process_pid" =~ ^[1-9][0-9]*$ || "$process_output" != "${process_pid}"$'\ntrue\ntrue\ntrue\ntrue' ]]; then
  printf 'Installed native process bridge failed: %s\n' "$process_output" >&2
  exit 1
fi
"$binary" run "$example"
case_example="$staging/usr/share/doc/galeikan/examples/case_lineage.gak"
case_output="$staging/report.json"
"$binary" run "$case_example" --case "$case_output"
"$binary" verify-case "$case_output"
python3 - "$case_output" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    document = json.load(stream)
assert document["format"] == "galeikan.case"
assert len(document["events"]) == 2
assert len(document["events"][0]["value"]["source_lineage"]) == 4
PY
if dpkg-deb --contents "$package" | grep -E '__pycache__|\.pyc'; then
  printf 'Package contains generated Python cache files.\n' >&2
  exit 1
fi
printf 'Dependencies: %s\n' "$(dpkg-deb --field "$package" Depends)"
printf 'Binary and example modes: '
stat -c '%a' "$binary" "$example" | paste -sd, -
