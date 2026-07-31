#!/usr/bin/env bash
# Regenerate the app icon: the visible spectrum, running out past violet into
# the dark. That is what "ultraviolet" means, and it is the same motif the
# website's strip uses — so the phone and the page look like one project.
#
# Built from gradient segments rather than drawn by hand, and checked in as a
# script plus one PNG, so a colour can be changed by editing a line instead of
# by opening an image editor nobody has.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=ios/UVWallet/Sources/Assets.xcassets/AppIcon.appiconset/AppIcon-1024.png
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

seg() { magick -size "240x${1}" "gradient:$2-$3" -rotate 90 "$T/seg_$4.png"; }
seg 83  '#2a0a0a' '#7f1d1d' 1   # deep red, almost out of sight
seg 116 '#7f1d1d' '#dc2626' 2
seg 108 '#dc2626' '#ca8a04' 3
seg 108 '#ca8a04' '#16a34a' 4
seg 100 '#16a34a' '#0891b2' 5
seg 92  '#0891b2' '#2563eb' 6
seg 92  '#2563eb' '#7c3aed' 7
seg 75  '#7c3aed' '#9D6BFF' 8   # the site's UV violet
seg 58  '#9D6BFF' '#0B0714' 9   # ...and out, past what an eye can see

magick "$T"/seg_*.png +append "$T/bar.png"
# The bar is uniform vertically, so a blur only blends neighbouring colours
# sideways — which is what a spectrum is, and it removes the segment seams.
magick "$T/bar.png" -blur 0x18 "$T/bar_s.png"
magick -size 832x240 xc:none -fill white -draw 'roundrectangle 0,0 831,239 120,120' "$T/mask.png"
magick "$T/bar_s.png" "$T/mask.png" -alpha off -compose CopyOpacity -composite "$T/bar_r.png"
magick -size 832x52 xc:none -fill white -draw 'roundrectangle 0,0 831,51 26,26' "$T/tmask.png"
magick "$T/bar_s.png" -resize 832x52! "$T/thin.png"
magick "$T/thin.png" "$T/tmask.png" -alpha off -compose CopyOpacity -composite \
  -channel A -evaluate multiply 0.5 +channel "$T/thin_r.png"
magick -size 1024x1024 xc:'#0B0714' \
  "$T/thin_r.png" -geometry +96+296 -compose over -composite \
  "$T/bar_r.png"  -geometry +96+392 -compose over -composite \
  "$T/thin_r.png" -geometry +96+700 -compose over -composite \
  -alpha remove -alpha off PNG24:"$OUT"
echo "wrote $OUT"
magick identify "$OUT"
