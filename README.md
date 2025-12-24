### This is a basic a packet sniffer maintained by @akshayrives and @vishalxdogra
AS OF NOW WE HAVE IMPLEMENTED THE FOLLOWING :
1. STEP 1 — Confirm base sniffer works (sanity test)
Goal: run the sniffer and see live one-line summaries.
What to do:
Run: sudo python3 all_sniffer.py -t 10 (sniffs for 10 seconds)
While it runs, open a browser on the same machine or phone hotspot and load a few pages; trigger DNS lookups (open websites), ping external host, etc.
What to expect:
One-line prints per packet with timestamp, src→dst, proto and length.
After 10s it prints final stats: captured count, top talkers, protocol counts.
If nothing appears:
Confirm interface is correct (try -i wlan0 or -i eth0).
Check permissions (run with sudo).
Try a known action: ping 8.8.8.8 in another terminal and watch for ICMP.

2. STEP 2 — Add PCAP dump (persist raw captures)
Goal: save raw packets to a .pcap file for later analysis in Wireshark.
What to change (conceptually):
When the script starts and you passed -o file.pcap, open a pcap writer bound to that filename.
For every packet processed, write it to the pcap (append).
On shutdown, close the pcap writer so file is valid.
How to test:
Run: sudo python3 all_sniffer.py -o test.pcap -t 15
Do some browsing or ping 1.1.1.1.
After the run, open test.pcap with Wireshark: wireshark test.pcap (or tcpdump -r test.pcap -n).
Verify packets are present and you can follow TCP streams or inspect DNS.
What to watch for:
If wireshark complains the pcap is corrupted, the writer wasn’t closed properly — test Ctrl-C behavior and ensure graceful shutdown closes file.

###  FUTURE IMPLEMENTATION PLANS:
3. STEP 3 — Make printed summaries richer (DNS + HTTP headlines)
Goal: when the sniffer sees DNS queries or clear-text HTTP requests, print human-friendly lines (DNS names, HTTP Host + path).
What to change (conceptually):
In the packet processing callback, detect DNS layer: if packet contains DNS and is a query, extract qname and print DNS q: <name>.
Detect HTTP request layer (plain HTTP, not HTTPS): extract Host and Path, print HTTP: Host /path.
Keep the existing one-line summary for everything else.
How to test:
Run sniffer.
From the device being monitored, open a plain HTTP URL (if possible) or use curl http://example.com (example.com often redirects to HTTPS; use a simple local HTTP test server e.g., python3 -m http.server 8000 and fetch it).
Do DNS lookups: dig +short example.com or open many sites and watch DNS lines.
Expected output lines:
... DNS q: example.com
... HTTP Host: example.local GET /index.html
Notes:
Most web browsing is HTTPS, so you will not see HTTP payloads for those sites. DNS names will still appear (unless DNS is over TLS/HTTPS/DoT).

4. STEP 4 — Build top-talkers that refresh live
Goal: keep a counters table of top source and destination IPs and print an updating snapshot every N seconds.
What to change (conceptually):
Maintain Counter objects for src and dst (already in script).
Spawn a tiny timer thread that wakes every N seconds (e.g., 5s) and prints the current top 5 sources/dests and protocol mix — without stopping sniffing.
Ensure printing from the timer is thread-safe (just print; minor mixing with packet lines is okay for now).
How to test:
Run sniffer with the timer enabled (or just run the script that includes it).
Generate traffic from multiple sources if possible (phone + laptop against internet).
Watch periodic top-talkers output.
Tips:
Keep the refresh interval modest (3–10s).
When you Ctrl-C, print the final summary as before.

5. STEP 5 — Add per-flow tracking (5-tuple flows)
Goal: group packets into flows identified by (src_ip, dst_ip, src_port, dst_port, proto) and track packet/byte counts, start time and last seen time.
What to change (conceptually):
On receiving an IP packet with TCP/UDP, compute a flow key tuple. For TCP, include ports; for ICMP or ARP, use protocol-specific keys.
Maintain a dict mapping flow_key -> {first_seen, last_seen, pkts, bytes}.
Update fields on each packet.
Implement flow expiry: periodically scan flows and remove ones whose last_seen is > timeout (e.g., 60s). When expiring, optionally print flow summary (duration, bytes, pkts).
How to test:
Run the sniffer.
Initiate a TCP connection (e.g., curl https://example.com), let it run, then finish.
After a minute, watch expired flows printed with stats.
Why useful:
Helps see connection durations, detect long-lived suspicious flows, or count bytes per connection.

6. STEP 6 — Implement rotation for PCAP files
Goal: avoid giant pcap files by rotating them either by size or time.
Conceptual approach:
Instead of a single writer, create a controller that opens a new pcap file with a timestamped name (e.g., capture_YYYYmmdd_HHMMSS.pcap).
Rotate when current file exceeds N MB or when time window passes (e.g., every 10 minutes).
On rotate: close old writer and open new writer. Continue writing without losing packets.
How to test:
Use a small rotation threshold (e.g., 1 MB) for testing.
Generate traffic until rotation occurs; verify two pcaps are created and both open in Wireshark.
Notes:
For high-reliability captures, prefer using dumpcap as the capture process and have your analyzer read the rotated files — reduces packet loss.

7. STEP 7 — Offload capture to dumpcap/tcpdump (reliability)
Goal: avoid packet drops under heavy load by letting a dedicated capture tool write pcaps, while your Python analyzer reads files or reads from a FIFO.
Two practical patterns:
A. Capture files + analyze offline
Run sudo dumpcap -i wlan0 -w capture.pcap (dumpcap handles rotation reliably).
Your script watches the capture directory and analyzes newly finished pcaps.
B. Named pipe (FIFO)
Create a FIFO file: mkfifo /tmp/pcappipe and run sudo tcpdump -i wlan0 -w - > /tmp/pcappipe
Your script reads from /tmp/pcappipe (as if it were a pcap file stream) and parses packets continuously.
This pattern avoids storing large pcaps on disk but requires careful handling of stream boundaries.
Why:
Scapy userland sniffing can drop packets at high rates; libpcap tools are optimized and can hand off writes to disk more reliably.
How to test:
Generate high-rate traffic (e.g., ping -f or hping3) and compare packet loss between direct Scapy sniff and dumpcap pipeline.

8. STEP 8 — Add simple alert rules (heuristics)
Goal: add the ability to raise alerts when simple conditions occur (e.g., many DNS NXDOMAINs, many SYNs without replies, traffic to suspicious IPs).
Conceptual examples:
If a flow has > X SYNs without ACKs in Y seconds → warn about possible scan.
If a single client triggers > N DNS queries per second → warn about noisy client.
Testing:
Simulate conditions with hping3 or script generating DNS queries, watch alerts printed.

9. STEP 9 — Small UX polish: arguments, logging, and config
Goal: make the tool friendly to use frequently.
Suggested changes:
Robust CLI (argparse) for all options (iface, filter, outfile, rotate-size, rotate-time, flow-timeout, refresh-interval).
Add logging levels (INFO/DEBUG) and an option to log to file.
