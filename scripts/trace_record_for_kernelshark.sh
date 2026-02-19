#!/bin/bash
# Record kernel trace and save trace.dat for viewing in KernelShark GUI.
# Usage: sudo ./scripts/trace_record_for_kernelshark.sh [duration_sec] [output.dat]
# Then open the output file in KernelShark: kernelshark trace.dat

DURATION="${1:-30}"
OUTPUT="${2:-/tmp/kernelshark_trace.dat}"
EVENTS="sched:sched_switch,sched:sched_wakeup,block:block_rq_issue,block:block_rq_complete,net:netif_receive_skb"

if ! command -v trace-cmd &>/dev/null; then
  echo "Install trace-cmd: sudo apt install trace-cmd"
  exit 1
fi

echo "Recording kernel trace for ${DURATION}s -> $OUTPUT"
echo "Events: $EVENTS"
trace-cmd record -e "$EVENTS" -o "$OUTPUT" sleep "$DURATION"
echo "Done. Open in KernelShark: kernelshark $OUTPUT"
trace-cmd report -i "$OUTPUT" | head -50
