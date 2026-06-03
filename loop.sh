#!/bin/bash
ITERATION=1
while true; do
    echo "━━━━━━━━━━ RALPH ITERATION: $ITERATION ━━━━━━━━━━"
    cat PROMPT.md | claude -p --dangerously-skip-permissions --model opus --output-format=stream-json --verbose
    
    git add -A
    git commit -m "Ralph iteration $ITERATION" --allow-empty
    
    ((ITERATION++))
    sleep 2
done
