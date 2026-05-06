# AutoNetIR Report Outline

## Problem Statement

Manual PCAP investigation is slow and requires security experience. Students and analysts need a simple dashboard that highlights known network attacks and explains why traffic is suspicious.

## Objective

Build a hybrid signature and behavior-based dashboard that detects SSH brute force-like attempts, HTTP login brute force, port scanning, ARP poisoning, and DoS activity.

## Methodology

The system extracts normalized events from PCAP files. Signature modules detect known attack indicators, behavior modules compare each host or flow with peers in the same capture, and the hybrid layer merges both into one alert.

## Attack Coverage

- SSH brute force-like attempts: repeated SYN attempts to port 22 plus abnormal SSH attempt volume.
- HTTP login brute force: repeated POST requests to login paths plus abnormal login request volume.
- Port scanning: SYN fan-out across many ports plus abnormal port diversity.
- ARP poisoning: multiple MAC addresses for one IP plus identity instability.
- DoS attack: SYN, ICMP, or HTTP request flood volume plus abnormal source-to-target traffic.

## Limitations

SSH and HTTPS payloads are encrypted, so the project cannot confirm credentials or login failure from ordinary PCAP data. Very small captures may produce weak behavior baselines.

## Future Work

Add configurable thresholds, live capture, SIEM export, extra protocols, and new attacks by adding a signature module, behavior module, and registry entry.
