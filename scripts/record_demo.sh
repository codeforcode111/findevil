#!/bin/bash
# Record the FinDevil demo video using asciinema
# Then convert to GIF and MP4

set -e

PROJECT_DIR="/Users/jiaweiyu/workfiles/hackthron-june"
OUTPUT_DIR="$PROJECT_DIR/workspace/demo_video"
mkdir -p "$OUTPUT_DIR"

CAST_FILE="$OUTPUT_DIR/findevil_demo.cast"
GIF_FILE="$OUTPUT_DIR/findevil_demo.gif"
MP4_FILE="$OUTPUT_DIR/findevil_demo.mp4"

echo "=== FinDevil Demo Video Recording ==="
echo ""
echo "Output directory: $OUTPUT_DIR"
echo ""

# Step 1: Record with asciinema
echo "[Step 1] Recording terminal session..."
echo "  The demo script will run automatically."
echo "  Press Ctrl+D or type 'exit' when done."
echo ""

asciinema rec "$CAST_FILE" \
  --title "FinDevil: Evidence-Contract Autonomous IR Agent" \
  --cols 120 \
  --rows 35 \
  --command "python $PROJECT_DIR/scripts/demo.py" \
  --overwrite

echo ""
echo "[Step 2] Converting to GIF..."
agg "$CAST_FILE" "$GIF_FILE" \
  --cols 120 \
  --rows 35 \
  --font-size 16 \
  --theme monokai

echo ""
echo "[Step 3] Converting to MP4..."
ffmpeg -y -i "$GIF_FILE" \
  -movflags faststart \
  -pix_fmt yuv420p \
  -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" \
  "$MP4_FILE" 2>/dev/null

echo ""
echo "=== Recording Complete ==="
echo "  Cast file: $CAST_FILE"
echo "  GIF file:  $GIF_FILE"
echo "  MP4 file:  $MP4_FILE"
echo ""
echo "Next steps:"
echo "  1. Review: asciinema play $CAST_FILE"
echo "  2. Upload MP4 to YouTube (unlisted)"
echo "  3. Paste YouTube URL into Devpost submission"
