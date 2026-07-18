//! Multicast flow module.
//! This module handles everything related to the source multicast flow.
//!
//! The standalone multicast sender is an ordinary [`crate::Connection`] that
//! generates QUIC packets intended to be sent to multiple receivers on the
//! multicast group. The application is responsible for taking the bytes
//! produced by [`crate::Connection::send`] and transmitting them to the
//! multicast (S,G) group with its own socket.

use std::net;

use super::McFlowInfo;
use super::MulticastData;
use crate::crypto::Algorithm;
use crate::multicast::error::McError;
use crate::packet;
use crate::test_utils::Pipe;
use crate::Config;
use crate::Connection;
use crate::ConnectionId;
use crate::Error;
use crate::Result;

/// Maps a negotiated AEAD [`Algorithm`] onto its TLS cipher suite code point.
fn cipher_suite_from_alg(alg: Algorithm) -> u16 {
    match alg {
        Algorithm::AES128_GCM => 0x1301,
        Algorithm::AES256_GCM => 0x1302,
        Algorithm::ChaCha20_Poly1305 => 0x1303,
    }
}

/// Creates a standalone multicast sender [`Connection`] for the given flow.
///
/// The returned connection generates 1-RTT short-header packets whose
/// Destination Connection ID is the `flow_id` and whose payload is placed in
/// `DATAGRAM` frames. The application queues data with
/// [`Connection::dgram_send`], calls [`Connection::send`], and transmits the
/// resulting bytes to the multicast (S,G) group itself.
///
/// The flow keys are the connection's own 1-RTT keys, derived from a secret
/// established during a throwaway in-memory handshake. That secret is exposed
/// via [`Connection::mc_flow_secret`] and must be advertised, together with the
/// [`Connection::mc_flow_cipher_suite`], to each multicast-capable client
/// through [`Connection::mc_provide_flow`].
///
/// `config` must be a server configuration (certificate and private key
/// loaded), have `DATAGRAM` frames enabled, disable peer verification, and set
/// application protocols. See [`crate::Config`].
pub fn mc_new_flow(
    config: &mut Config, flow_id: Vec<u8>, source_ip: net::IpAddr,
    group_ip: net::IpAddr, udp_port: u16,
) -> Result<Connection> {
    if !(1..=packet::MAX_CID_LEN as usize).contains(&flow_id.len()) {
        return Err(Error::Multicast(McError::McFlow));
    }

    let client_addr = Pipe::client_addr();
    let server_addr = Pipe::server_addr();

    // A server uses the peer's Source Connection ID as the Destination
    // Connection ID of its outgoing packets. By handing the throwaway client
    // the Flow ID as its SCID, every short-header packet the sender emits
    // carries DCID = Flow ID, with no further bookkeeping.
    let client_scid = ConnectionId::from_ref(&flow_id);

    let mut server_scid = [0; 16];
    crate::rand::rand_bytes(&mut server_scid[..]);
    let server_scid = ConnectionId::from_ref(&server_scid);

    let client = crate::connect(
        Some("quic.tech"),
        &client_scid,
        client_addr,
        server_addr,
        config,
    )?;
    let server =
        crate::accept(&server_scid, None, server_addr, client_addr, config)?;

    // Drive the handshake to completion and let both sides settle, so the
    // sender starts with no pending unicast frames (ACKs, HANDSHAKE_DONE, ...).
    let mut pipe = Pipe { client, server };
    pipe.handshake()
        .map_err(|_| Error::Multicast(McError::McFlow))?;
    pipe.advance()
        .map_err(|_| Error::Multicast(McError::McFlow))?;

    // Keep the server as the sender; the throwaway client is dropped.
    let mut sender = pipe.server;

    // Extract the 1-RTT application traffic secret; it becomes the flow secret.
    let (secret, cipher_suite) = {
        let seal = sender.crypto_ctx[packet::Epoch::Application]
            .crypto_seal
            .as_ref()
            .ok_or(Error::Multicast(McError::McFlow))?;

        (seal.secret().to_vec(), cipher_suite_from_alg(seal.alg()))
    };

    // The flow has its own packet-number space, starting at `first_pn`.
    let first_pn = sender.next_pkt_num;

    sender.multicast = Some(MulticastData {
        mc_flow_info: McFlowInfo {
            flow_id,
            source_ip,
            group_ip,
            udp_port,
            cipher_suite,
            first_pn,
            secret,
        },
        // Not meaningful on the sender; it never advertises MC_FLOW itself.
        mc_flow_sent: true,
        mc_flow_acked: true,
        flow_largest_pn: None, // Not meaningful.
        flow_open: None,       // Not meaningful.
    });

    Ok(sender)
}

impl Connection {
    /// Retrieves the [`McFlowInfo`].
    pub fn mc_get_flow_info(&self) -> Option<&McFlowInfo> {
        self.multicast.as_ref().map(|mc| &mc.mc_flow_info)
    }
}
