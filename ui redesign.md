I want to restyle the ThreatLens dashboard and forensic drawer without changing any typography 
Only touch layout, spacing, color usage, borders, and conditional rendering.

Files: frontend/src/App.tsx, frontend/src/components/ThreatTable.tsx, 
frontend/src/components/ForensicDrawer.tsx, frontend/src/components/ThroughputGauge.tsx, 
frontend/src/components/ThreatTrends.tsx, frontend/src/components/SystemHealthPanel.tsx

=== 1. Hero stat row (Critical Threats / High Severity / Mean Confidence / Dominant Vector) ===
Currently these are 4 identical bordered cards. Change to:
- Remove the card border/background from each stat. Replace with a single row divided by 
  vertical hairline dividers (1px, low-opacity border color) between stats — no border around 
  the row itself.
- Keep existing font sizes for the big numbers, just remove any card padding/background so the 
  number and label sit directly on the page background.
- Critical Threats value: when 0, render in a dimmed/muted text color (not the alert red) — 
  it should visually recede since there's nothing to act on. Only use the red/critical color 
  when the count is > 0.
- Add a one-line muted sub-caption under each stat (e.g. "of 16 total alerts", "across 6 
  detectors") using existing small/caption text style — just add the text, don't introduce a 
  new type size for it.

=== 2. ThroughputGauge — shrink and merge with SystemHealthPanel ===
The throughput chart currently renders as a large (~300px tall) mostly-empty line chart with a 
flat/pinned-to-top line — this is the y-axis scaling bug, check the domain/max calculation, it's 
likely hardcoded or not scaling to actual data range. Fix the axis scaling first.

Then restructure the layout: shrink the chart to a compact sparkline (~46-60px tall, fixed 
width ~300-340px) with a subtle gradient fill under the line, and place it inline in a single 
row alongside the key throughput figures (flows/s, pps, peak, bandwidth) as compact label/value 
pairs — not as separate stacked cards. Wrap the whole row in one thin-bordered container instead 
of one container per metric.

=== 3. Pipeline health panel ===
Currently 5 separate bordered cards in a grid. Change to one single bordered container, 
internally divided into columns by thin vertical dividers (like a table without cell borders), 
so it reads as one health strip rather than 5 disconnected boxes. Keep all existing labels/values, 
just change the container structure.

=== 4. Color semantics — apply consistently across ThreatTable, ThreatTrends, ForensicDrawer ===
Define/reuse these color roles and apply them consistently everywhere (don't introduce new colors 
beyond what's already in the palette — just make usage consistent):
- One color family reserved ONLY for severity (critical/high/moderate/low), used consistently in 
  ThreatTable severity pills, ForensicDrawer severity badge, and nowhere else.
- One accent color reserved ONLY for "live/streaming" state — the live status dot, WebSocket 
  connected indicator, "read-only" pipeline status, and any "just arrived" row highlight. 
  Don't reuse this color for anything unrelated to live state.
- Threat-vector trend line colors in ThreatTrends: keep 6 distinct colors, but make sure they're 
  visually distinct from the severity color family and the live-accent color so they don't get 
  confused with status colors elsewhere on the page.

=== 5. ThreatTable — new-alert visual feedback ===
When a new alert arrives via the WebSocket buffer and gets prepended/added to the table, add a 
brief highlight transition on that row (background color fades from the live-accent color at low 
opacity back to transparent over ~800-1000ms) so analysts notice new alerts without re-scanning 
the whole table. Use a CSS animation triggered by a "fresh" class added on insert and removed 
after the animation completes (or after N ms via a timeout/ref) — don't leave the class permanently 
attached.

=== 6. ThreatTable — confidence column ===
Currently confidence is shown as a bare percentage. Add a small (~4px tall, ~70px wide) horizontal 
bar next to/under the percentage, filled proportionally to the confidence value, colored using the 
severity color for that alert's severity tier. This gives a scannable visual magnitude alongside 
the exact number — keep the number as-is, just add the bar.

=== 7. ForensicDrawer — conditional evidence rendering by threat_class ===
This is the most important structural change. Currently every evidence card (Cryptographic 
Fingerprints/JA3/JA4/SNI, Fan-Out Cardinality, Shannon Entropy, IAT Variance, etc.) renders for 
every alert regardless of threat class, so unrelated fields show "N/A" or "0" at full visual 
weight.

Change ForensicDrawer to map evidence blocks to threat_class before rendering:
- Volumetric & Protocol DDoS: show PPS/Z-score, Flow Asymmetry Ratio, Inbound/Outbound 
  Pkts/Bytes, Observation Window. Hide the Cryptographic Fingerprints card and Fan-Out 
  Cardinality card entirely (don't render them, not even as N/A).
- Botnet C2 Beaconing: show Beacon Period, IAT Standard Deviation, JA3/JA4 (if present). 
  Hide Fan-Out Cardinality.
- DGA & DNS Tunneling: show DNS query metadata, N-gram score, Shannon Entropy. Hide 
  Cryptographic Fingerprints and Fan-Out Cardinality.
- Encrypted Malware: show JA3/JA4/SNI, SPLT sequences, FFT concentration. Hide Fan-Out 
  Cardinality.
- Reconnaissance Scan: show Fan-Out Cardinality, recon cardinalities, Source-IP Entropy. 
  Hide Cryptographic Fingerprints.
- Data Exfiltration: show Total Uploaded Bytes, Flow Asymmetry Ratio, Outbound Bytes. 
  Hide Cryptographic Fingerprints.

Implement this as a lookup object/map keyed by threat_class that returns which evidence card 
components to render, rather than a long if/else chain in the JSX. Any evidence field that IS 
relevant to the threat class but happens to be 0 or missing on this particular alert should still 
render, but in a visually muted/secondary style (lower opacity or muted text color) rather than 
the same weight as populated metrics — don't hide fields that are simply empty on this instance, 
only hide fields that don't apply to this threat class at all.

=== 8. ForensicDrawer — confidence context ===
Next to the existing confidence badge (e.g. "MODERATE (65%)"), add a small muted caption 
indicating which detector(s) contributed to this alert if that data is available in the evidence 
payload (e.g. "1 of 6 detectors triggered") — using existing small/caption text style. If that 
data isn't currently in the evidence payload, add a TODO comment instead of fabricating it.

=== 9. ForensicDrawer — raw JSON panel
Fix the current visual truncation at the bottom of the raw JSON payload viewer — it should either 
scroll cleanly within its container (overflow-y: auto with a fixed max-height) or show a fade-out 
gradient + "expand" affordance at the cutoff point, not crop a line mid-text.

=== 10. Typography hierarchy — establish a real type scale ===
Currently most text (labels, values, headers) sits at similar size/weight, making it hard to 
scan for what matters. Establish and apply a clear scale across App.tsx, ThreatTable.tsx, 
ForensicDrawer.tsx, ThroughputGauge.tsx, SystemHealthPanel.tsx:

Define these tiers once (as CSS variables or a shared constants file, not repeated inline):
- --text-display: for the 4 hero stat numbers (Critical Threats, High Severity, Mean Confidence 
  count) and the Forensic Dossier's headline threat class name. Largest weight/size on the page, 
  bold, tight letter-spacing (~-0.02em), tabular-nums for any numeric value so digits don't 
  jitter/misalign as they update live.
- --text-heading: for section titles (Real-Time Telemetry, Pipeline Health, Threat Vectors & 
  Trends, Live Stream, Forensic Dossier header) and the ForensicDrawer's "Classified Threat" 
  name. One clear step down from display, medium/semibold weight.
- --text-body: for table cell values, evidence card values, drawer field values — the actual data 
  people read row by row. Regular weight.
- --text-label: for all-lowercase or small-caps field labels (TIMESTAMP, SOURCE, DESTINATION, 
  PROTOCOL, etc.), column headers, and captions. Smallest size, muted color, slightly increased 
  letter-spacing for legibility at small size — but don't go all-caps if it isn't already, just 
  reuse whatever casing convention the codebase already uses.
- --text-mono: keep the existing monospace usage for IDs, IPs, hashes, timestamps, and raw JSON 
  exactly as-is — this tier already works, don't change it.

Apply consistently:
- Every stat label across the hero row, health panel, and throughput strip should be the SAME 
  size/weight (--text-label) — right now some labels are inconsistent sizes across panels.
- Every big number (Critical Threats count, High Severity count, Mean Confidence %) should be the 
  SAME size/weight (--text-display) — currently these don't clearly outrank their labels.
- In ForensicDrawer, the threat class name ("Volumetric & Protocol DDoS") should visually 
  outrank the field values below it (SOURCE, DESTINATION, PROTOCOL) by at least one full tier — 
  right now they read as nearly the same weight, which flattens the whole dossier.
- Table headers (TIMESTAMP, THREAT CLASS, SEVERITY, etc.) should be --text-label, clearly smaller 
  and dimmer than the --text-body row data beneath them, so the eye lands on data, not headers.
- Numeric values that update live (confidence %, PPS, flows/sec, latency figures) should use 
  tabular-nums (font-variant-numeric: tabular-nums) so digit width doesn't shift as values change.

Do not introduce a new font family — apply this scale using the existing typeface(s) already in 
the codebase, varying only size, weight, letter-spacing, and color to create the hierarchy.