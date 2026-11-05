# Port Scanner

First project in my 100 cybersecurity projects challenge. It's a TCP port scanner I wrote in Python to learn how sockets and threading work.

## What it does

You give it an IP (or hostname) and it tries to connect to every port in the range. Whatever accepts the connection gets reported as open. That's really it — it's a connect scanner, the simplest kind of scanner there is.

I wrote it with no dependencies on purpose. Everything is stdlib (`socket`, `argparse`, `concurrent.futures`), so it runs anywhere Python 3 is installed.

## Usage

```
python PortScanner.py                       # scans localhost, ports 1-1024
python PortScanner.py 192.168.1.1           # scan a specific host
python PortScanner.py 10.0.0.5 --ports 20-100 --workers 50
```

Output from a scan on my own machine:

```
[*] Scanning 1024 ports on 127.0.0.1 with 100 threads...

[+] Port 443    OPEN  (https)
[+] Port 80     OPEN  (http)

========================================
[*] Scan complete: 2 open port(s) found
    80/tcp  ->  http
    443/tcp  ->  https
========================================
```

(The http/https labels come from `getservbyport` — that's just a lookup of what *usually* runs on those ports. Something could easily be listening on port 80 that isn't a web server.)

## How it works

- `connect_ex()` does the actual check. Unlike `connect()` it returns an error code instead of raising, which makes it much nicer to call a few thousand times. Return value 0 = port open.
- Every connection has a 0.5s timeout. Without this, filtered ports hang for ages and the whole scan crawls.
- All ports get submitted to a `ThreadPoolExecutor` (100 threads by default). My first version scanned one port at a time and took forever. Threading fixed that completely, since each connection is basically just waiting on the network.

## Things I'd add next

- Banner grabbing (read the first bytes a service sends after connecting, like nmap does)
- UDP scanning
- Save results to a file

## Warning

Only use this on your own machines or things you have permission to scan. Scanning random hosts is illegal in a lot of places and also just rude.

Written as project 1/100.
