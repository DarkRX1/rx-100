# rx-100

100 cybersecurity projects, one at a time. Each project gets its own folder, a working tool, and a README that tells what actually happened, including the mistakes.

## House rules

- Small tools. Readable code. If the stdlib can do it, the stdlib does it.
- Every tool runs on the machine it was built for and was tested there, not just imagined.
- Nothing is shipped until I can explain every line and show the output that proves it works.
- READMEs describe what really happened. Failed attempts get written down because they taught more than the successes.
- Real device identifiers never leave this repo. MACs get masked, hostnames get renamed, private LAN details get scrubbed before any push.
- Password tools in category B attack self made targets only. Lab rules, always.

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
| 09 Password strength analyzer | 09-password-analyzer | B. Passwords | done | An entropy score says how random a password looks, not how guessable it is |
| 10 Hash cracker | 10-hash-cracker | B. Passwords | done | The same password scored 60 bits by one tool fell in 2 milliseconds to the other |

## What is next

Project 11 continues category B. Ten down, ninety to go.

Category A watched one home network from eight angles. Category B turns inward, starting with the weakest link in every system: the human-chosen secret. Projects 09 and 10 already argue with each other, which was the plan. The strength analyzer says what a password looks like on paper, and the cracker shows what it costs in practice.
