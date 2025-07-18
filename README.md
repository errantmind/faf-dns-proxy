# FaF DNS Proxy

`FaF DNS Proxy` is a cross-platform, encrypted DNS (DoT) proxy / forwarder written in Rust. It follows the general design philosophy of the [FaF Web Server](https://www.github.com/errantmind/faf).

**Project Structure**: This is a Cargo workspace containing two crates:
- `proxy/` - Main DNS proxy application
- `intercept/` - eBPF-based client identification library

FaF has been tested on Linux, Mac (M1), and Windows, and may work on other platforms as well.

![](diagram.png)

An example of the default (non-daemon) output, which gives some immediate insights into timings and upstream DNS resolver performance. This also demonstrates the 'client identification' feature with eBPF fast path (microsecond latency) and netlink fallback:

![Non-Daemon Output Example with 'client identification'](output2.png)

## Why Use This?

- You want the fastest DNS resolution available because you notice it speeds up your web browsing experience, among other areas.
- You don't want your ISP spying on your DNS queries.
- You want something that 'just works' out-of-the-box, with the default configuration.
- Perhaps you noticed occasional, mysterious delays that add 2-10 seconds to some page loads when using some other resolvers with DoT / DoH.

## Features

- DNS filtering (e.g. adblock - disabled by default)
- High-performance client identification using eBPF with netlink fallback (Linux only, disabled by default)
- Chart output to show the distribution of uncached dns query latencies (disabled by default)
- Full-duplex async design.
- Minimal parsing of DNS records to lower overhead.
- 'Shotgun' DNS queries to multiple upstream resolvers by default. The first reply wins.
- Caching of DNS answers (using the TTL on the answer), with optional minimum TTL override.
- TLS Session Caching (to avoid a full handshake when (re)connecting to upstream resolvers).
- Connection re-use.
- Automatic reconnections to DNS servers when connections are closed to ensure resolution doesn't wait on first establishing a connection.
- SNI disabled by default.

## How Does This Work?

At a basic level:

1. Your computer sends a DNS query (unencrypted) to FaF, which is running on your computer or another computer on your local network.
2. FaF checks its cache to see if there is an unexpired entry.
3. If it is in the cache, FaF returns the answer immediately.
4. If it is not in the cache, FaF encrypts your request and sends it to (one or more) upstream DNS resolvers.
5. Upon receiving a response from an upstream DNS resolver, FaF answers your device's original query.

You can run and use `faf-dns-proxy` locally, or deploy it somewhere and use it from there. I run it locally on each of my computers.

## Configuration

There is no configuration file as the defaults will serve most users well. If you want to add / edit the default upstream DNS providers, or the TTL override, make the necessary changes in the source file `statics.rs`.

## How To Use This (Linux)?

1. Clone this repository and build it using `cargo build --release -p faf-dns-proxy` (or with eBPF support: `cargo build --release -p faf-dns-proxy --features ebpf-client-ident`).
2. Stop your existing DNS resolver. See the next section for an example.
3. Run the binary with elevated privileges so it can listen on port 53 (DNS).
4. Navigate to some websites to check and see if it is working. You should see resolution information for each website you visit your terminal. If you don't, you may need to disable your brower's built-in DNS proxying service. This is usually in your brower's network settings and may be called `DoH` or `DNS over HTTPS`.
5. If it is working, disable your existing DNS resolver so it doesn't 'come back' (on reboot usually).
6. If your linux distro uses systemd, check out the example service in this repo to enable it to run on boot. You'll probably want to copy the `faf-dns-proxy` binary somewhere first.

If you have a problem, and suddenly realize you can't search the internet for answers anymore because your DNS is broken, just stop FaF and re-enable your previous DNS resolver.

## Simple Setup for Linux distros Packaged with `systemd-resolved`

- Follow the above steps. On step 2:
  - Stop systemd-resolved with `sudo systemctl stop --now systemd-resolved.service`.
  - Ensure your DNS resolution is pointed at FaF: Make a backup of `/etc/resolv.conf`. Then make a new `/etc/resolv.conf`. If running FaF on your local computer, this should be the only thing in the file:

```
nameserver 127.0.0.1
options no-check-names
```

- On step 5, disable systemd-resolved with `sudo systemctl disable --now systemd-resolved.service`.

## How To Use This (Windows)?

1. Clone this repository and build it using `cargo build --release -p faf-dns-proxy`.
2. Open Powershell and run the newly built binary. It should not require elevated privileges, but you may need to run Powershell as administrator on some versions of Windows.
3. Navigate to your system's network settings and change your system's primary DNS resolver to 127.0.0.1. Leave the 'alternative' empty.
4. Browse some websites to check and see if it is working. You should see resolution information for each website you visit in the Powershell window. If you don't, you may need to disable your brower's built-in DNS proxying service. This is usually in your brower's network settings and may be called `DoH` or `DNS over HTTPS`.
5. If it is working, you can script it to run at startup.

If you have a problem, and suddenly realize you can't search the internet for answers anymore because your DNS is broken, undo the changes to your system's DNS settings.

## Client Identification (Linux Only)

FaF DNS Proxy includes advanced client identification features to show which processes are making DNS requests:

- **eBPF Fast Path**: Uses kernel-level eBPF probes for microsecond-latency process identification
- **Netlink Fallback**: Falls back to netlink/procfs when eBPF is unavailable (~10ms overhead)
- **Build with**: `cargo build --release -p faf-dns-proxy --features ebpf-client-ident` for eBPF support
- **Runtime**: Use `--client-ident` flag, automatically detects and uses best available method
- **Force fallback**: Use `--force-netlink` to bypass eBPF for debugging

The output shows `[EBPF]` or `[NETLINK]` to indicate which method was used.

## Misc Notes

- By default, Firefox and some other browsers bypass the system's DNS, using their own built-in DoH. To reap the benefits of FaF while browsing, ensure this is disabled. This is usually somewhere in the browser's network settings.
- Only IPv4 upstream DNS resolvers are currently supported.
- Using the blocklist adds some delay as you might expect. In my tests the median overhead was about 10 microseconds locally.

## Code Tour

Get started by looking at `proxy/src/proxy.rs`.

## Contributions

Contributions are welcome, but please discuss before submitting a pull request. If a discussion leads to a pull request, please reference the \#issue in the pull request. Unsolicited pull requests will not be reviewed nor merged.

## License

All code is licensed under AGPL 3.0 unless an individual source file specifies otherwise.
