#!/bin/sh
set -e

TARGET="$1"
DEPTH="${2:-2}"
FORMAT="${3:-sarif}"
OUTPUT="${4:-temren-results.sarif}"
TIMEOUT="${5:-300}"
RATE="${6:-10}"
MAX_PAGES="${7:-50}"
AUTH_TOKEN="${8:-}"

if [ -z "$TARGET" ]; then
  echo "Error: target URL is required"
  exit 1
fi

CMD="temren scan --target \"$TARGET\" --depth \"$DEPTH\" --format \"$FORMAT\" --output \"$OUTPUT\" --timeout \"$TIMEOUT\" --rate \"$RATE\" --max-pages \"$MAX_PAGES\""

if [ -n "$AUTH_TOKEN" ]; then
  CMD="$CMD --auth-token \"$AUTH_TOKEN\""
fi

echo "Running: $CMD"
eval "$CMD"

echo "::notice::Temren scan complete. Results saved to $OUTPUT"
