# faf-dns-proxy Design

This is my 'work document', perhaps it will be useful to someone to illustrate my thought process while making this.

## General Flow
* Upon receiving a client request, check cache. If there is a valid entry, return that immedietly
* If no entry in the cache, send a request upstream for the data. While waiting for a response from upstream, move on to the next request (if any)
* Upon receiving a response from the server, check to see which client(s) requested it, and send them the response immediately, then add it to the cache
* Do some housekeeping on a separate thread to update the cache:
   * Loop through entries in the cache and decide whether or not to automatically update nearly expired entries or prune them. Use some heuristic to decide, like, if the client has fetched the server multiple times, and the most recent request was in the last 'n' hours, then update, else let expire or, if already expired, delete it

## General Design
* Do not parse a damn thing that isn't needed. Should only need to extract the individual bytes for the ID, TTL, and record type
* Use multiple threads and distribute each request coming from the client to different threads. Benchmark with and without this as it may be worse at keeping connections alive, as they are timed out so quickly by upstream DNS servers when not used (< 10 seconds for 1.1.1.1 and 8.8.8.8)
* Isolate TLS logic as much as makes sense, so eventually QUIC can be added easily
* It is ok if there are some occasional redundant requests between threads because of timing, like if requests for the same domain come in at the same time on different threads
* Fire off multiple requests upstream, per client request. Whichever response arrives first, send that to the client. Ignore subsequent responses by checking to see which client is waiting for the response (there won't be one). Discard the result, but collect local stats on latency, number of first place finishes, etc. Occasionally report these to the console if enabled by a command line switch.

## Command Line Switches
* Override upstream server list
* Show periodic statistics


Cache
* Cache is shared between threads. Access with a simple mutex
* Cache stores
   * The record type (A, CNAME, MX, etc)
   * The cached response (bytes), so no translation is necessary when sending to the client
   * Some information parsed from the response, like the TTL
   * The number of client requests for the server
   * The time of the most recent client request for the server

TLS
* Need an easy way to isolate the logic, and reconnect if EOF or a disconnect happens.
* Need to investigate all the ways to speed up resume

DNS
* Can modify queries without 'parsing', on the fly, to restrict them to particular record times, if this makes sense
