// Copyright (C) 2024, Cloudflare, Inc.
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

//! Aggregation of per-receiver multicast flow acknowledgements.
//!
//! One multicast flow is delivered to many receivers, each reporting the flow
//! packet numbers it received in `MC_ACK` frames over its own unicast
//! connection. For reliability the sender must retransmit a packet if *any*
//! receiver is missing it, and may free it only once *every* receiver has it.
//!
//! [`McAckAggregator`] combines those reports into a single "acknowledged by
//! every receiver" [`ranges::RangeSet`] — the intersection of what all
//! receivers received — to feed to the standalone sender with
//! [`crate::Connection::mc_on_flow_ack`].

use std::collections::HashMap;
use std::ops::Range;

use crate::ranges;

/// Reception state accumulated for a single receiver.
struct ReceiverAck {
    /// The union of every packet-number range the receiver has reported
    /// receiving, seeded at registration with `[0, first_pn)` so a late joiner
    /// counts every packet sent before it joined as already received.
    ///
    /// This is accumulated, never replaced: a receiver prunes and re-reports
    /// only deltas over its unicast connection, so replacing would drop
    /// packets the server already learned about.
    received: ranges::RangeSet,
}

/// Aggregates the multicast flow acknowledgements reported by all receivers
/// into a single acknowledged-by-every-receiver [`ranges::RangeSet`].
#[derive(Default)]
pub struct McAckAggregator {
    receivers: HashMap<u64, ReceiverAck>,
}

impl McAckAggregator {
    /// Creates an empty aggregator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a receiver, accountable from `first_pn` (the flow packet
    /// number advertised to it at join time). Everything below `first_pn` is
    /// seeded as received. Re-registering an existing receiver resets its
    /// state.
    pub fn add_receiver(&mut self, id: u64, first_pn: u64) {
        let mut received = ranges::RangeSet::default();

        if first_pn > 0 {
            received.insert(0..first_pn);
        }

        self.receivers.insert(id, ReceiverAck { received });
    }

    /// Removes a receiver that has left, so it no longer holds back the
    /// aggregate.
    pub fn remove_receiver(&mut self, id: u64) {
        self.receivers.remove(&id);
    }

    /// Drops per-receiver reception state for packet numbers up to and
    /// including `up_to`, which the sender has resolved (obtained with
    /// [`crate::Connection::mc_flow_prune_pn`]). Bounds memory as the flow
    /// progresses.
    pub fn prune(&mut self, up_to: u64) {
        for r in self.receivers.values_mut() {
            r.received.remove_until(up_to);
        }
    }

    /// Records the packet numbers a receiver reported as received (obtained
    /// with [`crate::Connection::mc_take_flow_ack`]), accumulating them into
    /// its reception set. Reports for an unknown receiver are ignored.
    pub fn record(&mut self, id: u64, received: &ranges::RangeSet) {
        if let Some(r) = self.receivers.get_mut(&id) {
            for range in received.iter() {
                r.received.insert(range);
            }
        }
    }

    /// Computes the set of flow packet numbers acknowledged by *every*
    /// receiver, ready to feed to the sender: the intersection of all
    /// receivers' reception sets. Returns an empty set if there are no
    /// receivers.
    pub fn aggregate(&self) -> ranges::RangeSet {
        let mut it = self.receivers.values();

        let mut acc = match it.next() {
            Some(r) => r.received.clone(),
            None => return ranges::RangeSet::default(),
        };

        for r in it {
            acc = intersect(&acc, &r.received);

            // Nothing is common to every receiver; no need to keep folding.
            if acc.len() == 0 {
                break;
            }
        }

        acc
    }
}

/// Intersection of two [`ranges::RangeSet`]s.
///
/// Relies on [`ranges::RangeSet::iter`] yielding ascending, non-overlapping,
/// half-open `[start, end)` ranges: a two-pointer merge that advances whichever
/// range ends first.
fn intersect(
    a: &ranges::RangeSet, b: &ranges::RangeSet,
) -> ranges::RangeSet {
    let mut out = ranges::RangeSet::default();

    let mut ia = a.iter();
    let mut ib = b.iter();

    let mut ra: Option<Range<u64>> = ia.next();
    let mut rb: Option<Range<u64>> = ib.next();

    loop {
        // Copy the endpoints out so the borrows of `ra`/`rb` end here, freeing
        // us to advance them below.
        let ((xs, xe), (ys, ye)) = match (&ra, &rb) {
            (Some(x), Some(y)) => ((x.start, x.end), (y.start, y.end)),

            // One list is exhausted: no further overlap is possible.
            _ => break,
        };

        let start = xs.max(ys);
        let end = xe.min(ye);

        if start < end {
            out.insert(start..end);
        }

        // Advance the range that ends first; drop both when they end together.
        if xe < ye {
            ra = ia.next();
        } else if ye < xe {
            rb = ib.next();
        } else {
            ra = ia.next();
            rb = ib.next();
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a `RangeSet` from a list of half-open ranges.
    fn set(ranges: &[Range<u64>]) -> ranges::RangeSet {
        let mut s = ranges::RangeSet::default();
        for r in ranges {
            s.insert(r.clone());
        }
        s
    }

    /// Collects the ranges of a `RangeSet` for comparison.
    fn ranges_of(s: &ranges::RangeSet) -> Vec<Range<u64>> {
        s.iter().collect()
    }

    #[test]
    fn intersect_basic() {
        assert_eq!(
            ranges_of(&intersect(&set(&[0..10, 20..30]), &set(&[5..25]))),
            vec![5..10, 20..25]
        );

        // Disjoint sets intersect to nothing.
        assert_eq!(
            ranges_of(&intersect(&set(&[0..5]), &set(&[10..15]))),
            vec![]
        );

        // Touching-but-not-overlapping ([0,5) and [5,10)) share nothing.
        assert_eq!(ranges_of(&intersect(&set(&[0..5]), &set(&[5..10]))), vec![]);
    }

    #[test]
    fn no_receivers_is_empty() {
        assert_eq!(McAckAggregator::new().aggregate().len(), 0);
    }

    #[test]
    fn single_receiver_is_its_own_set() {
        let mut agg = McAckAggregator::new();
        agg.add_receiver(1, 0);
        agg.record(1, &set(&[0..10]));

        assert_eq!(ranges_of(&agg.aggregate()), vec![0..10]);
    }

    #[test]
    fn acked_by_all_is_the_intersection() {
        let mut agg = McAckAggregator::new();
        agg.add_receiver(1, 0);
        agg.add_receiver(2, 0);
        agg.record(1, &set(&[0..10, 20..30]));
        agg.record(2, &set(&[5..25]));

        assert_eq!(ranges_of(&agg.aggregate()), vec![5..10, 20..25]);
    }

    #[test]
    fn packet_missing_at_one_receiver_is_excluded() {
        // Receiver 2 is missing packet 5.
        let mut agg = McAckAggregator::new();
        agg.add_receiver(1, 0);
        agg.add_receiver(2, 0);
        agg.record(1, &set(&[0..10]));
        agg.record(2, &set(&[0..5, 6..10]));

        assert_eq!(ranges_of(&agg.aggregate()), vec![0..5, 6..10]);
    }

    #[test]
    fn slowest_receiver_caps_the_aggregate() {
        let mut agg = McAckAggregator::new();
        agg.add_receiver(1, 0);
        agg.add_receiver(2, 0);
        agg.record(1, &set(&[0..100]));
        agg.record(2, &set(&[0..10]));

        assert_eq!(ranges_of(&agg.aggregate()), vec![0..10]);
    }

    #[test]
    fn late_joiner_does_not_hold_back_pre_join_packets() {
        // Receiver 1 has everything; receiver 2 joins at 50, so [0, 50) is
        // seeded as received and must not block the aggregate.
        let mut agg = McAckAggregator::new();
        agg.add_receiver(1, 0);
        agg.record(1, &set(&[0..100]));
        agg.add_receiver(2, 50);
        agg.record(2, &set(&[50..100]));

        assert_eq!(ranges_of(&agg.aggregate()), vec![0..100]);
    }

    #[test]
    fn record_accumulates_reported_deltas() {
        // A receiver prunes its own low end and later reports only a delta; the
        // aggregator must retain what it already learned.
        let mut agg = McAckAggregator::new();
        agg.add_receiver(1, 0);
        agg.record(1, &set(&[0..5]));
        agg.record(1, &set(&[10..11]));

        assert_eq!(ranges_of(&agg.aggregate()), vec![0..5, 10..11]);
    }

    #[test]
    fn prune_drops_resolved_state() {
        let mut agg = McAckAggregator::new();
        agg.add_receiver(1, 0);
        agg.record(1, &set(&[0..100]));

        // `up_to` is inclusive.
        agg.prune(49);

        assert_eq!(ranges_of(&agg.aggregate()), vec![50..100]);
    }

    #[test]
    fn removing_a_receiver_stops_it_constraining() {
        let mut agg = McAckAggregator::new();
        agg.add_receiver(1, 0);
        agg.add_receiver(2, 0);
        agg.record(1, &set(&[0..100]));
        agg.record(2, &set(&[0..10]));
        assert_eq!(ranges_of(&agg.aggregate()), vec![0..10]);

        agg.remove_receiver(2);
        assert_eq!(ranges_of(&agg.aggregate()), vec![0..100]);
    }
}
