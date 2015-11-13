This program was written in an attempt to learn rust and use it "in anger".

## Design

I chose a small but significant internal utility (pcap-prism) to replace
entirely. This program splits a single input pcap into multiple output pcaps.
It groups flows by the 5-tuple `(src, dst, srcport, dstport)` and outputs those
flows to individual pcap files.

The existing utility is multithreaded because it commonly outputs to pipes
instead of files. The other side of these pipes can be heavy processing
programs (i.e. snort) that potentially block. We thus stick a large buffer (in
the case of this program, the SPSC queue) in front of these processes. With this
in place, one process only blocks the others if its queue completely fills.

This design gains better tunability versus mucking with the size of the pipes
themselves.

The process also writes stats to a JSON file in the background for monitoring.

## Notes

I was planning on doing an internal presentation on this at some point, hence
the NOTES file. I also split out some commits (see 85e9 - 9699 for example)
so I could remember problems I ran into, and how I solved them.

## TODO

* Lots of cleanup is still needed. For reference, this program was initially
  written against a pre-1.0 version of rust.
* Investigate bindgen to remove lots of cruft.
* IPv6 support.
* Look at third-party SPSC library again.
* Possibly look at reviving my own zero-copy SPSC work. This quickly got into
  "advanced rust" territory but my knowledge is better now.
