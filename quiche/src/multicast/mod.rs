//! Minimal multicast extension for QUIC.

use std::net;
use std::sync::Arc;

use crate::crypto;
use crate::frame;
use crate::multicast::error::McError;
use crate::packet;
use crate::range_buf::RangeBuf;
use crate::ranges;
use crate::recovery::RecoveryOps;
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
    pub(crate) mc_flow_info: McFlowInfo,

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

    /// Client: the set of packet numbers successfully received on the flow, to
    /// be reported back to the server in `MC_ACK` frames over the unicast
    /// connection.
    flow_recv_pns: ranges::RangeSet,

    /// Client: whether new flow packet numbers have been received since the
    /// last `MC_ACK` was sent, i.e. an acknowledgement is scheduled.
    flow_ack_pending: bool,

    /// Server: the packet numbers reported as received by the client in
    /// `MC_ACK` frames, awaiting relay to the standalone sender connection.
    flow_acked_pns: Option<ranges::RangeSet>,
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

    /// Client: records a packet number received on the flow and schedules an
    /// `MC_ACK` to report it.
    fn record_flow_pn(&mut self, pn: u64) {
        self.flow_recv_pns.insert(pn..pn + 1);
        self.flow_ack_pending = true;
    }

    /// Client: builds the `MC_ACK` frame reporting the received flow packet
    /// numbers if one is scheduled, otherwise returns `None`.
    pub(crate) fn pending_ack_frame(&self) -> Option<frame::Frame> {
        if !self.flow_ack_pending || self.flow_recv_pns.len() == 0 {
            return None;
        }

        Some(frame::Frame::McAck {
            flow_id: self.mc_flow_info.flow_id.clone(),
            ack_delay: 0,
            ranges: self.flow_recv_pns.clone(),
        })
    }

    /// Client: marks the `MC_ACK` frame as transmitted.
    pub(crate) fn mark_ack_sent(&mut self) {
        self.flow_ack_pending = false;
    }

    /// Client: reschedules an `MC_ACK` after a loss, so the latest reception
    /// state is reported again.
    pub(crate) fn mark_ack_lost(&mut self) {
        self.flow_ack_pending = true;
    }

    /// Client: the `MC_ACK` frame is acknowledged by the server. Remove the
    /// reported packet numbers up to the largest acknowledged, so they are no
    /// longer re-sent in later `MC_ACK` frames.
    pub(crate) fn remove_ack_up_to(&mut self, largest: Option<u64>) {
        if let Some(largest) = largest {
            self.flow_recv_pns.remove_until(largest);
        }
    }

    /// Server: merges the packet numbers reported by a client `MC_ACK` into the
    /// set awaiting relay to the standalone sender connection.
    pub(crate) fn store_flow_ack(&mut self, ranges: ranges::RangeSet) {
        let acked = self
            .flow_acked_pns
            .get_or_insert_with(ranges::RangeSet::default);

        for r in ranges.iter() {
            acked.insert(r);
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
                flow_recv_pns: ranges::RangeSet::default(),
                flow_ack_pending: false,
                flow_acked_pns: None,
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
            flow_recv_pns: ranges::RangeSet::default(),
            flow_ack_pending: false,
            flow_acked_pns: None,
        });

        Ok(())
    }

    /// Processes a QUIC packet received on the multicast flow socket.
    ///
    /// The packet is a 1-RTT short-header packet whose Destination Connection
    /// ID is the Flow ID. It is decrypted with the flow key context in the flow
    /// packet-number space. Its `DATAGRAM` frames are delivered to the
    /// application exactly like unicast datagrams (retrieved with
    /// [`Connection::dgram_recv`]), and its `STREAM` frames are delivered into
    /// the receiver's stream reassembly buffers (retrieved with
    /// [`Connection::stream_recv`]). All other frame types are ignored.
    ///
    /// Unlike [`Connection::recv`], flow packets are never acknowledged and do
    /// not reset the unicast connection's idle timer.
    pub fn mc_recv(&mut self, buf: &mut [u8], _info: RecvInfo) -> Result<usize> {
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
        let largest = mc
            .flow_largest_pn
            .unwrap_or_else(|| mc.mc_flow_info.first_pn.saturating_sub(1));
        let pn = packet::decode_pkt_num(largest, hdr.pkt_num, hdr.pkt_num_len);

        let mut payload =
            packet::decrypt_pkt(&mut b, pn, hdr.pkt_num_len, payload_len, open)
                .map_err(|_| Error::Multicast(McError::McFlow))?;

        // Keep only the frames carrying application data; any other frame
        // type (ACK, flow control, ...) is meaningless on the one-way flow.
        while payload.cap() > 0 {
            let frame = frame::Frame::from_bytes(&mut payload, hdr.ty)
                .map_err(|_| Error::Multicast(McError::McFlow))?;

            match frame {
                frame::Frame::Datagram { data } => {
                    if self.dgram_recv_queue.is_full() {
                        self.dgram_recv_queue.pop();
                    }

                    self.dgram_recv_queue.push(data.into())?;
                    self.dgram_recv_count =
                        self.dgram_recv_count.saturating_add(1);
                },

                frame::Frame::Stream { stream_id, data } =>
                    self.mc_deliver_stream(stream_id, data)?,

                _ => (),
            }
        }

        let read = b.off();

        // Update the largest packet number seen on the flow and record it for
        // acknowledgement back to the server.
        if let Some(mc) = self.multicast.as_mut() {
            mc.flow_largest_pn = Some(match mc.flow_largest_pn {
                Some(largest) => largest.max(pn),
                None => pn,
            });

            mc.record_flow_pn(pn);
        }

        Ok(read)
    }

    /// Delivers a `STREAM` frame received on the flow into the receiver's
    /// stream reassembly buffers, so the application observes the data through
    /// [`Connection::stream_recv`] and [`Connection::readable`].
    ///
    /// This reuses the same primitives as the unicast receive path; it mirrors
    /// the `STREAM` handling of `Connection::process_frame`, minus the parts
    /// that only make sense on an acknowledged, flow-controlled connection
    /// (there is no return channel on the flow to raise limits or send ACKs).
    fn mc_deliver_stream(
        &mut self, stream_id: u64, data: RangeBuf,
    ) -> Result<()> {
        let max_rx_data_left = self.max_rx_data() - self.rx_data;

        // Get existing stream or create a new one, ignoring frames for a stream
        // that has already been closed and collected.
        let stream = match self.get_or_create_stream(stream_id, false) {
            Ok(v) => v,

            Err(Error::Done) => return Ok(()),

            Err(e) => return Err(e),
        };

        // Enforce the connection-level flow control limit; on the flow this
        // should never bind as limits are provisioned large up front.
        let max_off_delta = data.max_off().saturating_sub(stream.recv.max_off());

        if max_off_delta > max_rx_data_left {
            return Err(Error::FlowControl);
        }

        let was_readable = stream.is_readable();
        let priority_key = Arc::clone(&stream.priority_key);
        let was_draining = stream.recv.is_draining();

        stream.recv.write(data)?;

        if !was_readable && stream.is_readable() {
            self.streams.insert_readable(&priority_key);
        }

        self.rx_data += max_off_delta;

        if was_draining {
            self.flow_control.add_consumed(max_off_delta);
        }

        Ok(())
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

    /// Returns whether the client should schedule an `MC_ACK` frame for
    /// transmission on the unicast connection.
    pub(crate) fn mc_should_send_ack(&self) -> bool {
        !self.is_server &&
            self.multicast
                .as_ref()
                .is_some_and(|mc| mc.flow_ack_pending)
    }

    /// Returns the flow packet numbers reported as received by the client in
    /// `MC_ACK` frames since the previous call, for relay to the standalone
    /// sender connection. Server only.
    pub fn mc_take_flow_ack(&mut self) -> Option<ranges::RangeSet> {
        self.multicast
            .as_mut()
            .and_then(|mc| mc.flow_acked_pns.take())
    }

    /// Feeds flow packet numbers reported by the receivers (obtained on the
    /// unicast connection with [`Connection::mc_take_flow_ack`]) into the
    /// standalone sender's loss recovery, in the flow (Application) packet
    /// number space.
    ///
    /// This drives the sender's ordinary QUIC loss detection: packets missing
    /// from the reported ranges are eventually declared lost and their `STREAM`
    /// data is retransmitted by the next [`Connection::send`]. Call on the
    /// connection returned by [`mc_flow::mc_new_flow`].
    pub fn mc_on_flow_ack(&mut self, ranges: &ranges::RangeSet) -> Result<()> {
        // Nothing to acknowledge without a largest reported packet number.
        if ranges.last().is_none() {
            return Ok(());
        }

        let now = std::time::Instant::now();
        let epoch = packet::Epoch::Application;
        let handshake_status = self.handshake_status();
        let skip_pn = self.pkt_num_manager.skip_pn();

        let pid = self.paths.get_active_path_id()?;
        let p = self.paths.get_mut(pid)?;

        // The relayed report carries no meaningful delay; use zero.
        p.recovery.on_ack_received(
            ranges,
            0,
            epoch,
            handshake_status,
            now,
            skip_pn,
            &self.trace_id,
        )?;

        Ok(())
    }

    /// Returns the largest flow packet number the sender considers resolved
    /// (acknowledged by all receivers, or declared lost and re-sent under a new
    /// packet number). Receiver state up to it can be dropped with
    /// [`McAckAggregator::prune`]. Call on the connection returned by
    /// [`mc_flow::mc_new_flow`]; returns `None` when nothing has been resolved
    /// yet.
    pub fn mc_flow_prune_pn(&self) -> Option<u64> {
        // Everything below the oldest still-tracked packet is resolved.
        self.paths
            .get_active()
            .ok()?
            .recovery
            .oldest_sent_pkt_num(packet::Epoch::Application)
            .and_then(|oldest| oldest.checked_sub(1))
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
pub mod aggregator;

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

        // Providing a flow to a client without multicast support is a no-op: it
        // succeeds but installs nothing and schedules no advertisement.
        let (flow_id, src, grp, port, suite, first_pn, secret) = sample_flow();
        assert_eq!(
            pipe.server.mc_provide_flow(
                flow_id, src, grp, port, suite, first_pn, secret
            ),
            Ok(())
        );
        assert!(pipe.server.multicast.is_none());
        assert!(!pipe.server.mc_should_send_flow());
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

    /// Builds a server config with certificate and generous flow-control
    /// limits, so the standalone sender and receiver can move stream data.
    fn flow_config() -> Config {
        let mut config = Config::new(PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config
            .set_application_protos(&[b"proto1", b"proto2"])
            .unwrap();
        config.set_initial_max_data(100_000);
        config.set_initial_max_stream_data_bidi_local(100_000);
        config.set_initial_max_stream_data_bidi_remote(100_000);
        config.set_initial_max_stream_data_uni(100_000);
        config.set_initial_max_streams_bidi(10);
        config.set_initial_max_streams_uni(10);
        // Cap the packet size so a moderately sized stream deterministically
        // spans several flow packets.
        config.set_max_send_udp_payload_size(1200);
        config.set_max_recv_udp_payload_size(1200);
        config.verify_peer(false);
        config
    }

    /// Creates a standalone sender for a flow and an established receiver with
    /// the flow installed on it via an in-band `MC_FLOW` advertisement.
    fn sender_and_receiver(flow_id: Vec<u8>) -> (Connection, Pipe) {
        let mut sender_config = flow_config();
        let sender = crate::multicast::mc_flow::mc_new_flow(
            &mut sender_config,
            flow_id,
            "192.0.2.1".parse().unwrap(),
            "232.1.2.3".parse().unwrap(),
            4433,
        )
        .unwrap();

        let info = sender.mc_get_flow_info().unwrap().clone();

        let mut client_config = flow_config();
        client_config.set_multicast_support(true);
        let mut pipe = Pipe::with_client_config(&mut client_config).unwrap();
        pipe.handshake().unwrap();

        // The server advertises the sender's flow; the client installs it from
        // the MC_FLOW frame.
        pipe.server
            .mc_provide_flow(
                info.flow_id.clone(),
                info.source_ip,
                info.group_ip,
                info.udp_port,
                info.cipher_suite,
                info.first_pn,
                info.secret.clone(),
            )
            .unwrap();
        pipe.advance().unwrap();
        assert!(pipe.client.multicast.is_some());

        (sender, pipe)
    }

    fn flow_recv_info() -> RecvInfo {
        RecvInfo {
            from: Pipe::server_addr(),
            to: Pipe::client_addr(),
        }
    }

    #[test]
    fn flow_delivers_stream_to_receiver() {
        let (mut sender, mut pipe) = sender_and_receiver(vec![0x42; 8]);

        // The sender writes a unidirectional stream and produces a flow packet.
        let data = b"hello multicast";
        sender.stream_send(3, data, true).unwrap();

        let mut buf = [0u8; 1500];
        let (len, _) = sender.send(&mut buf).unwrap();

        pipe.client
            .mc_recv(&mut buf[..len], flow_recv_info())
            .unwrap();

        // The receiver reads the stream data delivered over the flow.
        let mut out = [0u8; 64];
        let (read, fin) = pipe.client.stream_recv(3, &mut out).unwrap();
        assert_eq!(&out[..read], data);
        assert!(fin);
    }

    #[test]
    fn flow_reception_is_acknowledged_to_server() {
        let (mut sender, mut pipe) = sender_and_receiver(vec![0x37; 8]);
        let first_pn = sender.mc_get_flow_info().unwrap().first_pn;

        // The client receives a flow packet and records its packet number.
        sender.stream_send(3, b"payload", true).unwrap();
        let mut buf = [0u8; 1500];
        let (len, _) = sender.send(&mut buf).unwrap();
        pipe.client
            .mc_recv(&mut buf[..len], flow_recv_info())
            .unwrap();

        // Flush the resulting MC_ACK to the server over the unicast connection.
        pipe.advance().unwrap();

        // The server can relay the reported reception to the sender.
        let acked = pipe.server.mc_take_flow_ack().expect("flow ack reported");
        assert_eq!(acked.last(), Some(first_pn));
    }

    #[test]
    fn flow_ack_triggers_retransmission() {
        let (mut sender, mut pipe) = sender_and_receiver(vec![0x51; 8]);
        let first_pn = sender.mc_get_flow_info().unwrap().first_pn;

        // Send a stream large enough to span several flow packets.
        let data = vec![0xa5u8; 6000];
        sender.stream_send(3, &data, true).unwrap();

        // Collect every flow packet the sender produces (packet i has packet
        // number first_pn + i).
        let mut packets: Vec<Vec<u8>> = Vec::new();
        let mut buf = [0u8; 1500];
        loop {
            match sender.send(&mut buf) {
                Ok((len, _)) => packets.push(buf[..len].to_vec()),
                Err(Error::Done) => break,
                Err(e) => panic!("send failed: {e:?}"),
            }
        }
        assert!(
            packets.len() >= 4,
            "need enough packets for loss detection, got {}",
            packets.len()
        );

        // Deliver every packet except the first, leaving a gap at the start of
        // the stream the receiver cannot yet read past.
        for pkt in &packets[1..] {
            let mut b = pkt.clone();
            pipe.client.mc_recv(&mut b, flow_recv_info()).unwrap();
        }
        let mut out = vec![0u8; data.len()];
        assert_eq!(pipe.client.stream_recv(3, &mut out), Err(Error::Done));

        // Report to the sender that every packet but the first was received.
        let mut acked = ranges::RangeSet::default();
        acked.insert(first_pn + 1..first_pn + packets.len() as u64);
        sender.mc_on_flow_ack(&acked).unwrap();

        // The sender now retransmits the lost stream data; deliver it.
        let mut retransmitted = false;
        loop {
            match sender.send(&mut buf) {
                Ok((len, _)) => {
                    let mut b = buf[..len].to_vec();
                    pipe.client.mc_recv(&mut b, flow_recv_info()).unwrap();
                    retransmitted = true;
                },
                Err(Error::Done) => break,
                Err(e) => panic!("send failed: {e:?}"),
            }
        }
        assert!(retransmitted, "sender did not retransmit after the ack");

        // With the gap filled, the receiver can read the whole stream.
        let mut got = Vec::new();
        loop {
            match pipe.client.stream_recv(3, &mut out) {
                Ok((read, fin)) => {
                    got.extend_from_slice(&out[..read]);
                    if fin {
                        break;
                    }
                },
                Err(Error::Done) => break,
                Err(e) => panic!("stream_recv failed: {e:?}"),
            }
        }
        assert_eq!(got, data);
    }
}
