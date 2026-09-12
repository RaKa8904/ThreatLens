# ThreatLens Passive Zeek Ingestion Policy
# ========================================
# Configures structured JSON streaming output, JA3/JA4 TLS cryptographic
# fingerprint extraction, and restricts logging to telemetry streams.

@load policy/tuning/json-logs.zeek

# Configure ISO8601 timestamps for JSON log writer
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# Base protocols (conn, dns, ssl) are loaded automatically by Zeek.
# Conditionally load JA3 fingerprinting if available in the image
@ifdef ( JA3::enable_ja3 )
@load policy/protocols/ssl/ja3
@endif

# Conditionally load JA4 fingerprinting if available in the image
@ifdef ( JA4::enable_ja4 )
@load ja4
@endif

event zeek_init()
    {
    # Silence non-essential logging streams to maximize pipeline throughput and minimize I/O
    @ifdef ( PacketFilter::LOG )
    Log::disable_stream(PacketFilter::LOG);
    @endif

    @ifdef ( LoadedScripts::LOG )
    Log::disable_stream(LoadedScripts::LOG);
    @endif

    @ifdef ( Reporter::LOG )
    Log::disable_stream(Reporter::LOG);
    @endif

    @ifdef ( Weird::LOG )
    Log::disable_stream(Weird::LOG);
    @endif

    @ifdef ( Notice::LOG )
    Log::disable_stream(Notice::LOG);
    @endif

    @ifdef ( Files::LOG )
    Log::disable_stream(Files::LOG);
    @endif

    @ifdef ( Software::LOG )
    Log::disable_stream(Software::LOG);
    @endif
    }

