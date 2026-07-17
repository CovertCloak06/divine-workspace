#!/data/data/com.termux/files/usr/bin/bash
# Frostline / WoS calibration runner (Termux, semi-automatic).
#
# For each calibration message: puts it on the clipboard, waits while you
# paste + send it in WoS chat, then screenshots the result via adb.
#
# One-time setup (Termux):
#   pkg install android-tools termux-api        # + install the Termux:API app
#   Settings -> Developer options -> Wireless debugging -> Pair device
#   adb pair localhost:PAIR_PORT                # 6-digit code from the dialog
#   adb connect localhost:CONNECT_PORT
#
# Then:  bash run.sh
# Send the shots/ folder back to Claude, or run measure.py yourself:
#   pkg install python python-pillow && python measure.py shots/
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$DIR/shots"
mkdir -p "$OUT"

command -v adb >/dev/null 2>&1 || { echo "adb missing: pkg install android-tools"; exit 1; }
adb get-state >/dev/null 2>&1 || {
  echo "adb is not connected. Run:"
  echo "  adb pair localhost:PAIR_PORT   (Developer options -> Wireless debugging)"
  echo "  adb connect localhost:CONNECT_PORT"
  exit 1
}
if ! command -v termux-clipboard-set >/dev/null 2>&1; then
  echo "termux-clipboard-set missing: pkg install termux-api (+ Termux:API app)."
  echo "Fallback: open each strings/*.txt in an editor and copy it manually."
fi

total=$(ls "$DIR"/strings/c*.txt | wc -l)
i=0
for f in "$DIR"/strings/c*.txt; do
  i=$((i+1))
  name="$(basename "$f" .txt)"
  if [ -e "$OUT/$name.png" ]; then
    echo "[$i/$total] $name already captured — skipping (delete shots/$name.png to redo)"
    continue
  fi
  if command -v termux-clipboard-set >/dev/null 2>&1; then
    termux-clipboard-set < "$f"
    echo "[$i/$total] $name is on the CLIPBOARD."
  else
    echo "[$i/$total] copy strings/$name.txt manually."
  fi
  echo "    -> switch to WoS, tap the chat box, PASTE, hit Send."
  echo "    -> make sure the WHOLE message bubble is visible, then return here"
  printf "    -> press Enter to screenshot... "
  read -r _
  adb exec-out screencap -p > "$OUT/$name.png"
  echo "saved shots/$name.png"
done
echo
echo "All $total captured. Next:"
echo "  python measure.py shots/        (needs: pkg install python python-pillow)"
echo "or send the shots/ folder back to Claude."
