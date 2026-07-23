// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Minimal multicast QUIC receiver.
//!
//! Connects to a `mumuquic-server`, advertises multicast support, receives the
//! `MC_FLOW` advertisement and the SDP over the unicast connection, joins the
//! multicast group, and bridges the flow's DATAGRAMs (RTP packets) to a local
//! UDP port a media player can consume:
//!
//! ```text
//! gst-launch-1.0 -v udpsrc address=127.0.0.1 port=22222 \
//!   caps="application/x-rtp,media=video,encoding-name=H264,payload=96,clock-rate=90000" ! \
//!   rtpjitterbuffer ! rtph264depay ! h264parse ! avdec_h264 ! videoconvert ! autovideosink sync=false
//! ```

#[macro_use]
extern crate log;

use std::net;

use ring::rand::*;

use socket2::Domain;
use socket2::Protocol;
use socket2::Socket;
use socket2::Type;

const MAX_DATAGRAM_SIZE: usize = 1350;

// Default unicast address of the mumuquic-server (override with argv[1]).
const SERVER_ADDR: &str = "127.0.0.1:4434";

// Local UDP endpoint the received RTP packets are forwarded to, for a media
// player (e.g. GStreamer/ffplay) to consume.
const RTP_OUT_ADDR: &str = "127.0.0.1:22222";

// Path the received SDP is written to.
const SDP_OUT_PATH: &str = "stream-recv.sdp";

// Server-initiated unidirectional stream carrying the SDP.
const SDP_STREAM_ID: u64 = 3;

fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut args = std::env::args();
    let cmd = args.next().unwrap();
    let peer_addr: net::SocketAddr = args
        .next()
        .unwrap_or_else(|| SERVER_ADDR.to_string())
        .parse()
        .unwrap_or_else(|_| {
            println!("Usage: {cmd} [server_addr]");
            std::process::exit(1);
        });

    // Set up the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Bind the unicast socket in the same family as the server.
    let bind_addr = if peer_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let mut socket =
        mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();
    let local_addr = socket.local_addr().unwrap();

    // Socket used to forward the received RTP packets to a local media player.
    let rtp_out = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let rtp_dst: net::SocketAddr = RTP_OUT_ADDR.parse().unwrap();

    // Create the QUIC configuration, advertising multicast support.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.verify_peer(false);
    config
        .set_application_protos(&[b"mumu-quic", b"mcquic", b"mc-quic"])
        .unwrap();
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_dgram(true, 65536, 65536);
    config.set_multicast_support(true);

    // Generate a random source connection ID.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();
    let scid = quiche::ConnectionId::from_ref(&scid);

    let mut conn = quiche::connect(
        Some("localhost"),
        &scid,
        local_addr,
        peer_addr,
        &mut config,
    )
    .unwrap();

    info!("connecting to {peer_addr}");

    // Send the initial flight.
    flush_send(&mut conn, &socket, &mut out);

    // Multicast receive socket, created once the flow has been advertised.
    let mut mc_sock: Option<mio::net::UdpSocket> = None;
    let mut mc_local: Option<net::SocketAddr> = None;

    // Accumulated SDP bytes received on the unicast stream.
    let mut sdp_buf: Vec<u8> = Vec::new();
    let mut sdp_done = false;

    loop {
        poll.poll(&mut events, conn.timeout()).unwrap();

        if events.is_empty() {
            conn.on_timeout();
        }

        // Drain the unicast socket.
        'unicast: loop {
            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock =>
                    break 'unicast,

                Err(e) => panic!("unicast recv() failed: {e:?}"),
            };

            let recv_info = quiche::RecvInfo {
                to: local_addr,
                from,
            };

            if let Err(e) = conn.recv(&mut buf[..len], recv_info) {
                error!("unicast recv failed: {e:?}");
            }
        }

        if conn.is_closed() {
            info!("connection closed: {:?}", conn.stats());
            break;
        }

        if conn.is_established() {
            // Read the SDP pushed by the server on its unidirectional stream.
            for s in conn.readable() {
                while let Ok((read, fin)) = conn.stream_recv(s, &mut buf) {
                    if s == SDP_STREAM_ID {
                        sdp_buf.extend_from_slice(&buf[..read]);

                        if fin && !sdp_done {
                            std::fs::write(SDP_OUT_PATH, &sdp_buf).ok();
                            sdp_done = true;
                            info!(
                                "received SDP ({} bytes), wrote {SDP_OUT_PATH}",
                                sdp_buf.len()
                            );
                        }
                    }
                }
            }

            // Join the multicast group once the flow has been advertised.
            if mc_sock.is_none() {
                if let Some(info) = conn.mc_get_flow_info() {
                    let (sock, local) =
                        join_multicast(info.group_ip, info.udp_port);

                    let mut sock = sock;
                    poll.registry()
                        .register(
                            &mut sock,
                            mio::Token(1),
                            mio::Interest::READABLE,
                        )
                        .unwrap();

                    info!(
                        "joined multicast flow ({}, {}):{}",
                        info.source_ip, info.group_ip, info.udp_port
                    );

                    mc_sock = Some(sock);
                    mc_local = Some(local);
                }
            }
        }

        // Drain the multicast socket: decode flow packets and forward their RTP
        // datagrams to the local media player.
        if let Some(sock) = mc_sock.as_mut() {
            'multicast: loop {
                let (len, from) = match sock.recv_from(&mut buf) {
                    Ok(v) => v,

                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock =>
                        break 'multicast,

                    Err(e) => panic!("multicast recv() failed: {e:?}"),
                };

                let recv_info = quiche::RecvInfo {
                    to: mc_local.unwrap(),
                    from,
                };

                if let Err(e) = conn.mc_recv(&mut buf[..len], recv_info) {
                    debug!("mc_recv dropped packet: {e:?}");
                    continue;
                }

                // Deliver each decoded DATAGRAM (one RTP packet) to the player.
                while let Ok(rtp_len) = conn.dgram_recv(&mut buf) {
                    if let Err(e) = rtp_out.send_to(&buf[..rtp_len], rtp_dst) {
                        error!("RTP forward failed: {e:?}");
                    }
                }
            }
        }

        // Send any pending unicast packets (ACKs, etc.).
        flush_send(&mut conn, &socket, &mut out);
    }
}

/// Drains a connection's pending packets to the unicast socket.
fn flush_send(
    conn: &mut quiche::Connection, socket: &mio::net::UdpSocket, out: &mut [u8],
) {
    loop {
        let (write, send_info) = match conn.send(out) {
            Ok(v) => v,

            Err(quiche::Error::Done) => break,

            Err(e) => {
                error!("send failed: {e:?}");
                conn.close(false, 0x1, b"fail").ok();
                break;
            },
        };

        if let Err(e) = socket.send_to(&out[..write], send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                break;
            }

            panic!("send() failed: {e:?}");
        }
    }
}

/// Creates a non-blocking UDP socket joined to the given multicast group.
fn join_multicast(
    group: net::IpAddr, port: u16,
) -> (mio::net::UdpSocket, net::SocketAddr) {
    let sock = match group {
        net::IpAddr::V4(group) => {
            let sock =
                Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
                    .unwrap();
            sock.set_reuse_address(true).unwrap();

            let bind: net::SocketAddr = (net::Ipv4Addr::UNSPECIFIED, port).into();
            sock.bind(&bind.into()).unwrap();

            sock.join_multicast_v4(&group, &net::Ipv4Addr::UNSPECIFIED)
                .unwrap();
            sock
        },

        net::IpAddr::V6(group) => {
            let sock =
                Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
                    .unwrap();
            sock.set_reuse_address(true).unwrap();

            let bind: net::SocketAddr = (net::Ipv6Addr::UNSPECIFIED, port).into();
            sock.bind(&bind.into()).unwrap();

            // Interface index 0 selects the default multicast interface.
            sock.join_multicast_v6(&group, 0).unwrap();
            sock
        },
    };

    sock.set_nonblocking(true).unwrap();

    let sock: std::net::UdpSocket = sock.into();
    let local = sock.local_addr().unwrap();

    (mio::net::UdpSocket::from_std(sock), local)
}
