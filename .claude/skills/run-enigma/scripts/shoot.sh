#!/usr/bin/env bash
# Screenshot an Enigma page with headless Chromium.
#
#   shoot.sh <url> <out.png> [width] [height] [scroll_y]
#
# With scroll_y, the page is loaded inside a same-origin iframe and scrolled
# before capture — headless --screenshot always captures from the top, and a
# cross-origin iframe cannot be scrolled by script.
set -euo pipefail

URL="${1:?usage: shoot.sh <url> <out.png> [w] [h] [scroll_y]}"
OUT="${2:?missing output path}"
W="${3:-1280}"
H="${4:-1500}"
SCROLL="${5:-0}"

CHROME=$(ls /opt/pw-browsers/chromium-*/chrome-linux/chrome 2>/dev/null | head -1)
[ -n "$CHROME" ] || { echo "no chromium under /opt/pw-browsers" >&2; exit 1; }

TARGET="$URL"
WORK=""
if [ "$SCROLL" != "0" ]; then
  # Serve a wrapper next to a saved copy so the iframe is same-origin.
  WORK=$(mktemp -d)
  curl -sS "$URL" -o "$WORK/page.html"
  cat > "$WORK/wrap.html" <<HTML
<style>body{margin:0}iframe{width:${W}px;height:${H}px;border:0}</style>
<iframe src="/page.html" scrolling="no"
        onload="this.contentWindow.scrollTo(0,${SCROLL})"></iframe>
HTML
  python3 -m http.server 8099 --bind 127.0.0.1 --directory "$WORK" >/dev/null 2>&1 &
  WRAP_PID=$!
  trap 'kill $WRAP_PID 2>/dev/null; rm -rf "$WORK"' EXIT
  until curl -sS -o /dev/null http://127.0.0.1:8099/wrap.html 2>/dev/null; do :; done
  TARGET="http://127.0.0.1:8099/wrap.html"
fi

# The dbus/GPU errors on stderr are normal in a container and not failures.
"$CHROME" --headless --disable-gpu --no-sandbox --hide-scrollbars \
  --window-size="$W,$H" --virtual-time-budget=6000 \
  --screenshot="$OUT" "$TARGET" 2>/dev/null || true

[ -s "$OUT" ] || { echo "screenshot came out empty: $OUT" >&2; exit 1; }
echo "wrote $OUT ($(stat -c%s "$OUT") bytes)"
