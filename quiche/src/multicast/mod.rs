//! Minimal multicast extension for QUIC.

use std::net;

use crate::crypto;
use crate::frame;
use crate::multicast::error::McError;
use crate::packet;
use crate::BufFactory;
use crate::Connection;
use crate::Error;
use crate::RecvInfo;
use crate::Result;

/// Maps a TLS cipher suite code point onto its AEAD [`crypto::Algorithm`].
pub(crate) fn alg_from_cipher_suite(
    cipher_suite: u16,
) -> Result<crypto::Algorithm> {
    match cipher_suite {
        0x1301 => Ok(crypto::Algorithm::AES128_GCM),
        0x1302 => Ok(crypto::Algorithm::AES256_GCM),
        0x1303 => Ok(crypto::Algorithm::ChaCha20_Poly1305),
        _ => Err(Error::Multicast(McError::McFlow)),
    }
}

/// Minimal multicast structure.
/// The objective of this structure is to handle as much multicast-related task
/// as possible.
pub struct MulticastData {
    /// Multicast flow information.
    /// TODO: for now, only consider a single multicast flow.
    mc_flow_info: McFlowInfo,

    /// Server: whether the `MC_FLOW` frame is currently scheduled to be sent
    /// (i.e. it has been queued and not yet marked as transmitted). It mirrors
    /// the one-shot handling of `HANDSHAKE_DONE`: on loss it is reset to
    /// scheduled, on acknowledgement it is retired.
    mc_flow_sent: bool,

    /// Server: whether the `MC_FLOW` frame has been acknowledged by the client.
    /// Once acknowledged, the frame is no longer retransmitted.
    mc_flow_acked: bool,

    /// Client: the flow key context, derived from the flow secret and cipher
    /// suite, used to decrypt packets received on the flow.
    flow_open: Option<crypto::Open>,

    /// Client: the largest packet number successfully decrypted on the flow.
    /// It is the basis for packet-number reconstruction; before any packet has
    /// been decrypted, `First Packet Number` is used instead.
    flow_largest_pn: Option<u64>,
}

impl MulticastData {
    /// Builds the `MC_FLOW` frame to advertise the flow if it is still
    /// scheduled for (re)transmission, otherwise returns `None`.
    pub(crate) fn pending_flow_frame(&self) -> Option<frame::Frame> {
        if self.mc_flow_sent {
            return None;
        }

        Some(self.mc_flow_info.to_frame())
    }

    /// Marks the `MC_FLOW` frame as transmitted.
    pub(crate) fn mark_flow_sent(&mut self) {
        self.mc_flow_sent = true;
    }

    /// Marks the `MC_FLOW` frame as acknowledged, retiring it.
    pub(crate) fn mark_flow_acked(&mut self) {
        // Ensure a scheduled retransmission is aborted.
        self.mc_flow_sent = true;
        self.mc_flow_acked = true;
    }

    /// Reschedules the `MC_FLOW` frame after a loss, unless it was already
    /// acknowledged.
    pub(crate) fn mark_flow_lost(&mut self) {
        if !self.mc_flow_acked {
            self.mc_flow_sent = false;
        }
    }
}

impl McFlowInfo {
    /// Builds the `MC_FLOW` frame advertising this flow.
    fn to_frame(&self) -> frame::Frame {
        frame::Frame::McFlow {
            flow_id: self.flow_id.clone(),
            source_ip: self.source_ip,
            group_ip: self.group_ip,
            udp_port: self.udp_port,
            cipher_suite: self.cipher_suite,
            first_pn: self.first_pn,
            secret: self.secret.clone(),
        }
    }
}

impl<F: BufFactory> Connection<F> {
    /// Registers, on the server, a multicast flow to advertise to the client
    /// over its unicast connection.
    ///
    /// The `MC_FLOW` frame describing the flow is scheduled for transmission
    /// and retransmitted using normal QUIC loss recovery until
    /// acknowledged.
    ///
    /// The client MUST have advertised the `multicast_support` transport
    /// parameter; otherwise this returns [`McError::McFlow`].
    // The arguments map one-to-one onto the fields of the MC_FLOW frame, so
    // they are passed explicitly rather than bundled into a struct.
    #[allow(clippy::too_many_arguments)]
    pub fn mc_provide_flow(
        &mut self, flow_id: Vec<u8>, source_ip: net::IpAddr,
        group_ip: net::IpAddr, udp_port: u16, cipher_suite: u16, first_pn: u64,
        secret: Vec<u8>,
    ) -> Result<()> {
        if !self.is_server {
            error!("MC provide flow 1");
            return Err(Error::Multicast(McError::McFlow));
        }

        // A server MUST NOT send MC_FLOW to a client that did not advertise
        // multicast support.
        if !self.peer_transport_params.multicast_support {
            error!("MC provide flow 2");
            return Ok(());
        }

        if !(1..=packet::MAX_CID_LEN as usize).contains(&flow_id.len()) {
            error!("MC provide flow 3");
            return Err(Error::Multicast(McError::McFlow));
        }

        if self.multicast.is_none() {
            self.multicast = Some(MulticastData {
                mc_flow_info: McFlowInfo {
                    flow_id,
                    source_ip,
                    group_ip,
                    udp_port,
                    cipher_suite,
                    first_pn,
                    secret,
                },
                mc_flow_sent: false,
                mc_flow_acked: false,
                flow_open: None,
                flow_largest_pn: Some(first_pn),
            });
        }

        Ok(())
    }

    /// Creates state on the client for the advertised multicast flow.
    // The arguments map one-to-one onto the fields of the MC_FLOW frame, so
    // they are passed explicitly rather than bundled into a struct.
    #[allow(clippy::too_many_arguments)]
    pub fn mc_new_from_info(
        &mut self, flow_id: Vec<u8>, source_ip: net::IpAddr,
        group_ip: net::IpAddr, udp_port: u16, cipher_suite: u16, first_pn: u64,
        secret: Vec<u8>,
    ) -> Result<()> {
        // Derive the flow key context from the secret, exactly as a 1-RTT
        // application traffic secret (RFC 9001).
        let alg = alg_from_cipher_suite(cipher_suite)?;
        let flow_open = crypto::Open::from_secret(alg, &secret)
            .map_err(|_| Error::Multicast(McError::McFlow))?;

        self.multicast = Some(MulticastData {
            mc_flow_info: McFlowInfo {
                flow_id,
                source_ip,
                group_ip,
                udp_port,
                cipher_suite,
                first_pn,
                secret,
            },
            // Not meaningful on the client; the client never sends MC_FLOW.
            mc_flow_sent: true,
            mc_flow_acked: true,
            flow_open: Some(flow_open),
            flow_largest_pn: Some(first_pn),
        });

        Ok(())
    }

    /// Processes a QUIC packet received on the multicast flow socket.
    ///
    /// The packet is a 1-RTT short-header packet whose Destination Connection
    /// ID is the Flow ID. It is decrypted with the flow key context in the flow
    /// packet-number space, and its `DATAGRAM` frames are delivered to the
    /// application exactly like unicast datagrams (retrieved with
    /// [`Connection::dgram_recv`]). All other frame types are ignored.
    ///
    /// Unlike [`Connection::recv`], flow packets are never acknowledged and do
    /// not reset the unicast connection's idle timer.
    pub fn mc_recv(&mut self, buf: &mut [u8], _info: RecvInfo) -> Result<usize> {
        // Phase 1: decrypt the packet and collect its datagrams while borrowing
        // the (immutable) flow key context.
        let (datagrams, pn, read) = {
            let mc = self
                .multicast
                .as_ref()
                .ok_or(Error::Multicast(McError::McFlow))?;
            let open = mc
                .flow_open
                .as_ref()
                .ok_or(Error::Multicast(McError::McFlow))?;
            let flow_id = &mc.mc_flow_info.flow_id;

            let mut b = octets::OctetsMut::with_slice(buf);

            let mut hdr = packet::Header::from_bytes(&mut b, flow_id.len())
                .map_err(|_| Error::Multicast(McError::McFlow))?;

            // Only 1-RTT short-header packets addressed to the Flow ID belong to
            // the flow.
            if hdr.ty != packet::Type::Short || &hdr.dcid[..] != &flow_id[..] {
                return Err(Error::Multicast(McError::McFlow));
            }

            let payload_len = b.cap();

            packet::decrypt_hdr(&mut b, &mut hdr, open)
                .map_err(|_| Error::Multicast(McError::McFlow))?;

            // Reconstruct the full packet number in the flow space.
            let largest = mc.flow_largest_pn.unwrap_or_else(|| {
                mc.mc_flow_info.first_pn.saturating_sub(1)
            });
            let pn =
                packet::decode_pkt_num(largest, hdr.pkt_num, hdr.pkt_num_len);

            let mut payload = packet::decrypt_pkt(
                &mut b,
                pn,
                hdr.pkt_num_len,
                payload_len,
                open,
            )
            .map_err(|_| Error::Multicast(McError::McFlow))?;

            // A client MUST ignore any non-DATAGRAM frame on the flow.
            let mut datagrams = Vec::new();
            while payload.cap() > 0 {
                let frame = frame::Frame::from_bytes(&mut payload, hdr.ty)
                    .map_err(|_| Error::Multicast(McError::McFlow))?;

                if let frame::Frame::Datagram { data } = frame {
                    datagrams.push(data);
                }
            }

            (datagrams, pn, b.off())
        };

        // Phase 2: update flow state and deliver datagrams (mutable borrows of
        // disjoint fields).
        if let Some(mc) = self.multicast.as_mut() {
            mc.flow_largest_pn = Some(match mc.flow_largest_pn {
                Some(largest) => largest.max(pn),
                None => pn,
            });
        }

        for data in datagrams {
            if self.dgram_recv_queue.is_full() {
                self.dgram_recv_queue.pop();
            }

            self.dgram_recv_queue.push(data.into())?;
            self.dgram_recv_count = self.dgram_recv_count.saturating_add(1);
        }

        Ok(read)
    }

    /// Returns the flow traffic secret of a multicast sender connection, to be
    /// advertised to clients via [`Connection::mc_provide_flow`].
    pub fn mc_flow_secret(&self) -> Option<&[u8]> {
        self.multicast
            .as_ref()
            .map(|mc| mc.mc_flow_info.secret.as_slice())
    }

    /// Returns the cipher suite of a multicast sender connection, to be
    /// advertised to clients via [`Connection::mc_provide_flow`].
    pub fn mc_flow_cipher_suite(&self) -> Option<u16> {
        self.multicast
            .as_ref()
            .map(|mc| mc.mc_flow_info.cipher_suite)
    }

    /// Returns whether the server should schedule an `MC_FLOW` frame for
    /// transmission on the unicast connection.
    pub(crate) fn mc_should_send_flow(&self) -> bool {
        self.is_server &&
            self.multicast.as_ref().is_some_and(|mc| !mc.mc_flow_sent)
    }
}

#[derive(Clone)]
/// Handle information about a multicast flow.
pub struct McFlowInfo {
    /// The Flow ID.
    pub flow_id: Vec<u8>,

    /// The source IP address of the flow.
    pub source_ip: net::IpAddr,

    /// The group IP address of the flow.
    pub group_ip: net::IpAddr,

    /// The destination UDP port.
    pub udp_port: u16,

    /// The cipher suite used to decrypt packets from the multicast flow.
    pub cipher_suite: u16,

    /// The first packet number that we can expect to receive on the multicast
    /// flow.
    pub first_pn: u64,

    /// The TLS secret used to generate the decryption key for the multicast
    /// flow.
    pub secret: Vec<u8>,
}

pub mod error;
pub mod mc_flow;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::Pipe;
    use crate::Config;
    use crate::PROTOCOL_VERSION;

    /// Builds a client config that advertises multicast support.
    fn mc_client_config(multicast_support: bool) -> Config {
        let mut config = Config::new(PROTOCOL_VERSION).unwrap();
        config
            .set_application_protos(&[b"proto1", b"proto2"])
            .unwrap();
        config.set_initial_max_data(30);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.set_ack_delay_exponent(8);
        config.verify_peer(false);
        config.set_multicast_support(multicast_support);
        config
    }

    fn sample_flow() -> (Vec<u8>, net::IpAddr, net::IpAddr, u16, u16, u64, Vec<u8>)
    {
        (
            vec![0x11; 8],
            "192.0.2.1".parse().unwrap(),
            "232.1.2.3".parse().unwrap(),
            4433,
            0x1301,
            42,
            vec![0xab; 32],
        )
    }

    #[test]
    fn server_advertises_flow_to_capable_client() {
        let mut client_config = mc_client_config(true);
        let mut pipe = Pipe::with_client_config(&mut client_config).unwrap();
        pipe.handshake().unwrap();

        let (flow_id, src, grp, port, suite, first_pn, secret) = sample_flow();
        pipe.server
            .mc_provide_flow(
                flow_id.clone(),
                src,
                grp,
                port,
                suite,
                first_pn,
                secret.clone(),
            )
            .unwrap();

        // The server has a pending, un-acked flow advertisement.
        assert!(pipe.server.mc_should_send_flow());

        // Flush the MC_FLOW frame to the client and its ACK back.
        pipe.advance().unwrap();

        // The client installed the advertised flow.
        let mc = pipe.client.multicast.as_ref().unwrap();
        assert_eq!(mc.mc_flow_info.flow_id, flow_id);
        assert_eq!(mc.mc_flow_info.source_ip, src);
        assert_eq!(mc.mc_flow_info.group_ip, grp);
        assert_eq!(mc.mc_flow_info.udp_port, port);
        assert_eq!(mc.mc_flow_info.cipher_suite, suite);
        assert_eq!(mc.mc_flow_info.first_pn, first_pn);
        assert_eq!(mc.mc_flow_info.secret, secret);

        // The server retired the frame after acknowledgement.
        let server_mc = pipe.server.multicast.as_ref().unwrap();
        assert!(server_mc.mc_flow_acked);
        assert!(!pipe.server.mc_should_send_flow());
    }

    #[test]
    fn provide_flow_requires_client_support() {
        // Client does not advertise multicast support.
        let mut client_config = mc_client_config(false);
        let mut pipe = Pipe::with_client_config(&mut client_config).unwrap();
        pipe.handshake().unwrap();

        let (flow_id, src, grp, port, suite, first_pn, secret) = sample_flow();
        assert_eq!(
            pipe.server.mc_provide_flow(
                flow_id, src, grp, port, suite, first_pn, secret
            ),
            Err(Error::Multicast(McError::McFlow))
        );
    }

    #[test]
    fn provide_flow_rejects_non_server() {
        let mut client_config = mc_client_config(true);
        let mut pipe = Pipe::with_client_config(&mut client_config).unwrap();
        pipe.handshake().unwrap();

        // A client must not originate an MC_FLOW advertisement.
        let (flow_id, src, grp, port, suite, first_pn, secret) = sample_flow();
        assert_eq!(
            pipe.client.mc_provide_flow(
                flow_id, src, grp, port, suite, first_pn, secret
            ),
            Err(Error::Multicast(McError::McFlow))
        );
    }
}
