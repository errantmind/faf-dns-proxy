# FaF DNS Proxy
`FaF DNS Proxy` is a Linux (only) DoT proxy / forwarder written in Rust. It follows the design philosophy of the [FaF Web Server](https://www.github.com/errantmind/faf).

This is an experimental project and not 'production-ready', although I do use it on my own machines. I am working to clean up the code for easier comprehension and to add the last few remaining features. 

Currently, the TTL is IGNORED and all IPs are cached indefinitely. This actually doesn't cause as many issues as you might think, I too was surprised, but this will be fixed in the next version.

## Why Use This?

* You want the fastest DNS resolution available because you notice it speeds up your web browsing experience, among other areas
* You don't want to use unencrypted DNS because you don't want your ISP spying on your traffic and selling it to third parties
* You want something that 'just works' optimally out-of-the-box, with the default configuration, and you don't feel like configuring `systemd-resolved`, `unbound`, etc
* Perhaps you have noticed occasional, mysterious delays that add 2-10 seconds to some page loads when using some other resolvers with DoT / DoH


## How Does This Work?

At a basic level:
1. Your computer sends a DNS query (unencrypted) to FaF, which is running on your computer or another computer on your local network.
2. FaF checks its cache to see if there is an unexpired entry
3. If it is in the cache, FaF returns the answer immediately
4. If it is not in the cache, FaF encrypts your request and sends it to (one or more) upstream DNS resolvers
5. Upon receiving a response from an upstream DNS resolver, FaF answers your device's query

## How To Use This?

1. Clone this repository and build it using `cargo +nightly build --release`
2. Stop your existing DNS resolver. See the next section for an example.
3. Run the binary with elevated privileges so it can listen on port 53 (DNS)
4. Navigate to some websites to check and see if it is working
5. If it is working, disable your existing DNS resolver so it doesn't 'come back' (on reboot usually)
6. If your linux distro uses systemd, check out the example service in this repo to enable it to run on boot. You'll probably want to copy the `faf-dns-proxy` binary somewhere first.

If you have a problem, and suddenly realize you can't search the internet for answers anymore because your DNS is broken, just stop FaF and re-enable your previous DNS resolver.

## Simple Setup for Distros Packaged with `systemd-resolved`

* Follow the above steps. On step 2:
   * Stop systemd-resolved with `sudo systemctl stop --now systemd-resolved.service`
   * Ensure your DNS resolution is pointed at FaF: Make a backup of `/etc/resolv.conf`. Then make a new `/etc/resolv.conf`. If running FaF on your local computer, this should be the only thing in the file:

```
nameserver 127.0.0.1
options no-check-names
```
* On step 5, disable systemd-resolved with `sudo systemctl disable --now systemd-resolved.service`



## Features

* 'Shotgun' DNS queries to multiple upstream resolvers by default. The first reply wins
* Caching of DNS answers (using the TTL on the answer)
* TLS Session caching (to avoid a full handshake when (re)connecting to upstream resolvers)
* Event driven, asynchronous design. Avoids the extra latency of synchronous networking wherever possible
* Designed to minimize the most latency intensive part of encrypted DNS: (re)connecting to upstream DNS resolvers. Instead of using a generic connection pool, FaF uses an event-activated thread for each upstream resolver, to ensure back-to-back requests reuse an existing connection upstream. This is important as most upstream resolvers unilaterally terminate connections after being idle for ~10 seconds, so we want to minimize reconnects by keeping established connections alive as long as possible


## Requirements and How-To

FaF DNS Proxy requires:
* linux x86_64
* nightly Rust


## Code Tour

Just look at `epoll.rs`, everything is either there or referenced there and, even then, it is only ~200 lines of code.

Aside: a `no_std` version of this project compiles to a total of only ~400 lines of assembly TEXT, and 7KB binary, although it takes a few modifications to get there: the only real dependency on std is threading, so if we eliminate it and change to a `1 process per core` model instead of `1 thread per core` we get a very minimal setup. The performance is ~1% worse. If you are interested in this, let's discuss.

## Contributions
Contributions are welcome, but please discuss before submitting a pull request. If a discussion leads to a pull request, please reference the \#issue in the pull request. Unsolicited pull requests will not be reviewed nor merged.

Any and all contributions, unless otherwise specified, will be licensed under the license specified by this project (below). All contributors agree to automatically and irrevocably relicense their code to match the project license if the project license changes. All contribitors, by submitting contributions as a pull request (or in any other form), agree to these terms. Any license changes will occur as a bump in versioning and the previous license will remain in effect for the previous version.


## License
All code is licensed under AGPL 3.0 unless an individual source file specifies otherwise.

If you don't like the license, convince me.
