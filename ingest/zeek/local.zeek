# ThreatLens Passive Zeek Ingestion Policy
# ========================================
# Configures structured JSON streaming output, JA3/JA4 TLS cryptographic
# fingerprint extraction, and restricts logging to telemetry streams.

@load policy/tuning/json-logs.zeek
@load policy/protocols/conn
@load policy/protocols/dns
@load policy/protocols/ssl

# Enable JA3 client and server fingerprint extraction
@load policy/protocols/ssl/ja3

redef JSON::timestamps = JSON::TS_ISO8601;

event zeek_init()
    {
    # Silence non-essential logging streams to maximize pipeline throughput and minimize I/O
    local quiet_streams: set[Log::ID] = {
        PacketFilter::LOG,
        LoadedScripts::LOG,
        Reporter::LOG,
        Weird::LOG,
        Notice::LOG,
        Files::LOG,
        Software::LOG
    };

    for ( stream in quiet_streams )
        {
        Log::disable_stream(stream);
        }
    }
