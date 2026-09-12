#!/usr/bin/env bash
set -e

LOG_DIR="${LOG_DIR:-/logs}"
PCAP_DIR="${PCAP_DIR:-/pcaps}"
ZEEK_POLICY="${ZEEK_POLICY:-/zeek/local.zeek}"
MODE="${MODE:-watch}"

mkdir -p "$LOG_DIR"
cd "$LOG_DIR"

echo "[ThreatLens-Zeek] Ingestion daemon starting..."
echo "[ThreatLens-Zeek] Mode: $MODE | Log directory: $LOG_DIR | PCAP directory: $PCAP_DIR"

process_pcap() {
    local pcap_path="$1"
    if [ -f "$pcap_path" ]; then
        echo "[ThreatLens-Zeek] Processing capture: $pcap_path"
        zeek -C -r "$pcap_path" "$ZEEK_POLICY" Log::default_logdir="$LOG_DIR"
        echo "[ThreatLens-Zeek] Ingestion completed for: $pcap_path"
    fi
}

if [ "$MODE" = "live" ]; then
    INTERFACE="${INTERFACE:-eth0}"
    echo "[ThreatLens-Zeek] Starting live passive inspection on interface: $INTERFACE"
    exec zeek -C -i "$INTERFACE" "$ZEEK_POLICY" Log::default_logdir="$LOG_DIR"

elif [ "$MODE" = "replay" ]; then
    echo "[ThreatLens-Zeek] Running one-shot PCAP replay..."
    for pcap in "$PCAP_DIR"/*.pcap "$PCAP_DIR"/*.pcapng; do
        [ -e "$pcap" ] || continue
        process_pcap "$pcap"
    done
    echo "[ThreatLens-Zeek] One-shot replay completed. Sleeping to maintain logs container..."
    exec tail -f /dev/null

else
    # Default: Watch directory mode
    echo "[ThreatLens-Zeek] Processing initial capture files..."
    for pcap in "$PCAP_DIR"/*.pcap "$PCAP_DIR"/*.pcapng; do
        [ -e "$pcap" ] || continue
        process_pcap "$pcap"
    done

    echo "[ThreatLens-Zeek] Monitoring $PCAP_DIR for new capture replays..."
    if command -v inotifywait >/dev/null 2>&1; then
        inotifywait -m -e close_write,moved_to --format "%w%f" "$PCAP_DIR" | while read -r new_pcap; do
            case "$new_pcap" in
                *.pcap|*.pcapng)
                    process_pcap "$new_pcap"
                    ;;
            esac
        done
    else
        # Polling fallback loop
        while true; do
            for pcap in "$PCAP_DIR"/*.pcap "$PCAP_DIR"/*.pcapng; do
                [ -e "$pcap" ] || continue
                process_pcap "$pcap"
            done
            sleep 5
        done
    fi
fi
