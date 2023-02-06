# FaF DNS Proxy

`FaF DNS Proxy` is a cross-platform, encrypted DNS (DoT) proxy / forwarder written in Rust. It follows the general design philosophy of the [FaF Web Server](https://www.github.com/errantmind/faf).

FaF has been tested on Linux and Windows and may work on other platforms as well.

## Why Use This?

- You want the fastest DNS resolution available because you notice it speeds up your web browsing experience, among other areas
- You don't want your ISP spying on your DNS queries
- You want something that 'just works' out-of-the-box, with the default configuration
- Perhaps you have noticed occasional, mysterious delays that add 2-10 seconds to some page loads when using some other resolvers with DoT / DoH

## Features

- 'Shotgun' DNS queries to multiple upstream resolvers by default. The first reply wins
- Caching of DNS answers (using the TTL on the answer), with optional minimum TTL override
- TLS Session Caching (to avoid a full handshake when (re)connecting to upstream resolvers)
- Full-duplex async design
- Connection re-use and automatic reconnections when connections are closed

## How Does This Work?

At a basic level:

1. Your computer sends a DNS query (unencrypted) to FaF, which is running on your computer or another computer on your local network.
2. FaF checks its cache to see if there is an unexpired entry
3. If it is in the cache, FaF returns the answer immediately
4. If it is not in the cache, FaF encrypts your request and sends it to (one or more) upstream DNS resolvers
5. Upon receiving a response from an upstream DNS resolver, FaF answers your device's original query

## How To Use This (Linux)?

1. Clone this repository and build it using `cargo +nightly build --release`
2. Stop your existing DNS resolver. See the next section for an example.
3. Run the binary with elevated privileges so it can listen on port 53 (DNS)
4. Navigate to some websites to check and see if it is working. You should see resolution information for each website you visit your terminal. If you don't, you may need to disable your brower's built-in DNS proxying service. This is usually in your brower's network settings and may be called `DoH` or `DNS over HTTPS`
5. If it is working, disable your existing DNS resolver so it doesn't 'come back' (on reboot usually)
6. If your linux distro uses systemd, check out the example service in this repo to enable it to run on boot. You'll probably want to copy the `faf-dns-proxy` binary somewhere first.

If you have a problem, and suddenly realize you can't search the internet for answers anymore because your DNS is broken, just stop FaF and re-enable your previous DNS resolver.

## How To Use This (Windows)?

1. Clone this repository and build it using `cargo +nightly build --release`
2. Navigate to your system's network settings and change your system's primary DNS resolver to 127.0.0.1. Leave the 'alternative' empty.
3. Open Powershell with administrator privileges (so it can listen on port 53 (DNS)) and run the newly built binary
4. Navigate to some websites to check and see if it is working. You should see resolution information for each website you visit in the Powershell window. If you don't, you may need to disable your brower's built-in DNS proxying service. This is usually in your brower's network settings and may be called `DoH` or `DNS over HTTPS`
5. If it is working, you can add a shortcut to the binary to your startup folder.
6. If your linux distro uses systemd, check out the example service in this repo to enable it to run on boot. You'll probably want to copy the `faf-dns-proxy` binary somewhere first.

If you have a problem, and suddenly realize you can't search the internet for answers anymore because your DNS is broken, undo the changes to your system's DNS settings.

## Simple Setup for Linux distros Packaged with `systemd-resolved`

- Follow the above steps. On step 2:
  - Stop systemd-resolved with `sudo systemctl stop --now systemd-resolved.service`
  - Ensure your DNS resolution is pointed at FaF: Make a backup of `/etc/resolv.conf`. Then make a new `/etc/resolv.conf`. If running FaF on your local computer, this should be the only thing in the file:

```
nameserver 127.0.0.1
options no-check-names
```

- On step 5, disable systemd-resolved with `sudo systemctl disable --now systemd-resolved.service`

## Misc Notes

- By default, Firefox and some other browsers bypass the system's DNS, using their own built-in DoH. To reap the benefits of FaF while browsing, ensure this is disabled. This is usually somewhere in the browser's network settings.

## Code Tour

Just look at `proxy.rs`, everything is either there or referenced there.

## Contributions

Contributions are welcome, but please discuss before submitting a pull request. If a discussion leads to a pull request, please reference the \#issue in the pull request. Unsolicited pull requests will not be reviewed nor merged.

Any and all contributions, unless otherwise specified, will be licensed under the license specified by this project (below). All contributors agree to automatically and irrevocably relicense their code to match the project license if the project license changes. All contribitors, by submitting contributions as a pull request (or in any other form), agree to these terms. Any license changes will occur as a bump in versioning and the previous license will remain in effect for the previous version.

## License

All code is licensed under AGPL 3.0 unless an individual source file specifies otherwise.

If you don't like the license, convince me.
