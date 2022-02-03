/*
FaF is a cutting edge, high performance web server
Copyright (C) 2021  James Bates

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/


// faf spawns one thread per core, meaning each thread can handle 1024 connections. 
// If we don't UNSHARE, then we can only handle 'n' total connections across all threads (instead of 'each')
pub const MAX_CONN: usize = 64;

// the buffer size of the request buffer. Currently set to 4096 bytes (most common page size)
pub const REQ_BUFF_SIZE: usize = 4096;

// the buffer size of both the response buffers. Currently set to 4096 bytes (most common page size)
pub const RES_BUFF_SIZE: usize = 4096;

// our syscall to wait for epoll events will timeout every 1ms. This is marginally faster in some cases than a longer timeout
pub const EPOLL_TIMEOUT_MILLIS: isize = 1000;

// 4096 bytes page size / 12 byte epoll_event size = ~340. This size reduces page faults
pub const MAX_EPOLL_EVENTS_RETURNED: usize = 340;

// isolate to core 0
pub const CPU_CORE_CLIENT_LISTENER: usize = 0;

pub struct UpstreamDnsServer(pub &'static str, pub &'static str);
pub const UPSTREAM_DNS_SERVERS: [UpstreamDnsServer; 4] = [
   UpstreamDnsServer("one.one.one.one", "1.1.1.1"),
   UpstreamDnsServer("one.one.one.one", "1.0.0.1"),
   UpstreamDnsServer("dns.google", "8.8.8.8"),
   UpstreamDnsServer("dns.google", "8.8.4.4"),
];
