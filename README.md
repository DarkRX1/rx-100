# rx-100

100 cybersecurity projects, one at a time. Each project gets its own folder, a working tool, and a README that tells what actually happened, including the mistakes.

## House rules

- Small tools. Readable code. If the stdlib can do it, the stdlib does it.
- Every tool runs on the machine it was built for and was tested there, not just imagined.
- Nothing is shipped until I can explain every line and show the output that proves it works.
- READMEs describe what really happened. Failed attempts get written down because they taught more than the successes.
- Real device identifiers never leave this repo. MACs get masked, hostnames get renamed, private LAN details get scrubbed before any push.

## The roadmap so far

| Project | Folder | Category | Status | One lesson it taught |
|---|---|---|---|---|
| 01 Port scanner | 01-port-scanner | A. Network | done | A TCP connect scan looks simple until you meet your own firewall |
| 02 Network monitor | 02-network-monitor | A. Network | done | Polling fast is easy, polling honestly is not |
| 03 ARP spoofing detector | 03-arp-detector | A. Network | done | Two devices claiming one MAC is a loud alarm if you listen |
| 04 Personal firewall | 04-firewall | A. Network | done | Rules that drop packets should also tell you why |
| 05 Packet sniffer | 05-packet-sniffer | A. Network | done | Raw sockets show you the wire, not the story you expected |
| 06 Network topology mapper | 06-topology-mapper | A. Network | done | Parse output by keyword, never by column position |
| 07 Bandwidth monitor | 07-bandwidth-monitor | A. Network | done | Calibrate every measurement against a second instrument |
| 08 Network log analyzer | 08-log-analyzer | A. Network | done | A switch never echoes a frame back to you. Test on a virtual wire |

## What is next

Project 09 starts category B. A password strength analyzer, built to say why a password is weak instead of just scoring it.

Category A is eight tools that all watch the same home network from different angles. Scan it, watch it, detect lies on it, gate it, read it, map it, count it, then judge the logs it leaves behind. The best findings came from the tools disagreeing with each other.
