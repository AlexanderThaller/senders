#!/usr/bin/env bash
# Regenerate the senders icon set from the vector mark defined below.
#
# The mark is a sealed letter: a paper envelope on the teal accent, closed with
# a wax seal. Geometry lives here and nowhere else -- every file under
# crates/web/icons is derived from `mark()`, so a change to the drawing is a
# change to this script followed by a re-run.
#
# The 64-unit grid is chosen so the envelope lands on whole pixels at 16x16
# (x 12..52 and y 16..48 are multiples of four): at favicon size the edges stay
# crisp instead of smearing over two rows.
#
# Needs rsvg-convert (librsvg) and magick (ImageMagick 7).
set -euo pipefail

cd "$(dirname "$0")/.."
out=crates/web/icons
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

teal="#1f6b5f"   # --accent, light theme
paper="#faf9f6"  # --paper, light theme
wax="#a94438"    # sealing wax; a logo colour, not one of the CSS tokens

# mark <corner-radius> <content-scale>
#
# Corner radius 14 is the standalone tile. Platforms that apply their own mask
# (iOS, Android adaptive icons) get radius 0 -- a full-bleed square -- and a
# content scale that keeps the envelope clear of whatever they crop.
mark() {
  local rx="$1" scale="$2" open="" close=""
  if [ "$scale" != "1" ]; then
    open="<g transform=\"translate(32 32) scale($scale) translate(-32 -32)\">"
    close="</g>"
  fi
  cat <<EOF
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64" role="img" aria-label="senders">
  <title>senders</title>
  <rect width="64" height="64" rx="$rx" fill="$teal"/>
  $open<rect x="12" y="16" width="40" height="32" rx="4" fill="$paper"/>
  <path d="M12 18.5H52L32 36Z" fill="$teal"/>
  <circle cx="32" cy="35" r="7.5" fill="$wax"/>$close
</svg>
EOF
}

render() { rsvg-convert -w "$2" -h "$2" "$1" -o "$3"; }

# --- scalable, served as-is --------------------------------------------------

mark 14 1 > "$out/favicon.svg"

# Safari's pinned tab wants one flat colour on transparency, so the envelope is
# the silhouette and the flap is cut out of it (evenodd) rather than painted.
# The seal is dropped here on purpose: in a single colour it fills the flap's
# notch and the envelope stops reading as one.
cat > "$out/mask-icon.svg" <<EOF
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64" role="img" aria-label="senders">
  <title>senders</title>
  <path fill="#000" fill-rule="evenodd" d="M16 16H48A4 4 0 0 1 52 20V44A4 4 0 0 1 48 48H16A4 4 0 0 1 12 44V20A4 4 0 0 1 16 16ZM12 18.5H52L32 36Z"/>
</svg>
EOF

# --- raster ------------------------------------------------------------------

# favicon.ico still carries the sizes Windows and older browsers ask for.
for s in 16 32 48; do render "$out/favicon.svg" "$s" "$tmp/ico-$s.png"; done
magick "$tmp/ico-16.png" "$tmp/ico-32.png" "$tmp/ico-48.png" "$out/favicon.ico"

# Standalone PNG favicons: Chrome and Firefox prefer these over the .ico when
# both are linked, and unlike the .ico they are reachable and cacheable on
# their own.
cp "$tmp/ico-16.png" "$out/favicon-16x16.png"
cp "$tmp/ico-32.png" "$out/favicon-32x32.png"

# PWA icons, used as drawn.
render "$out/favicon.svg" 192 "$out/icon-192.png"
render "$out/favicon.svg" 512 "$out/icon-512.png"

# iOS rounds the corners itself and dislikes transparency, so: square, full
# bleed, content pulled in a little from the corners it clips.
mark 0 0.88 > "$tmp/apple.svg"
render "$tmp/apple.svg" 180 "$out/apple-touch-icon.png"

# Android adaptive icons may crop to any shape inside the central 80% circle.
# At scale 1 the envelope's diagonal is exactly that circle's diameter, so it
# would sit right on the line; 0.9 gives it room.
mark 0 0.9 > "$tmp/maskable.svg"
render "$tmp/maskable.svg" 192 "$out/icon-maskable-192.png"
render "$tmp/maskable.svg" 512 "$out/icon-maskable-512.png"

printf 'wrote:\n'; ls -1 "$out"
