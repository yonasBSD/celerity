use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

use bytes::Bytes;

use crate::{Multipart, OutboundItem, PeerEvent, ProtocolError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternAction<PeerId> {
    Send { peer: PeerId, item: OutboundItem },
    Deliver { peer: PeerId, message: Multipart },
}

#[derive(Debug, Clone)]
pub struct PubCore<PeerId> {
    subscriptions: HashMap<PeerId, HashMap<Bytes, usize>>,
}

impl<PeerId> Default for PubCore<PeerId> {
    fn default() -> Self {
        Self {
            subscriptions: HashMap::new(),
        }
    }
}

impl<PeerId> PubCore<PeerId>
where
    PeerId: Copy + Eq + Hash,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn remove_peer(&mut self, peer: PeerId) {
        self.subscriptions.remove(&peer);
    }

    pub fn on_peer_event(&mut self, peer: PeerId, event: PeerEvent) -> Result<(), ProtocolError> {
        match event {
            PeerEvent::Subscription { subscribe, topic } => {
                let peer_topics = self.subscriptions.entry(peer).or_default();
                if subscribe {
                    // SUB peers may repeat the same topic, so track a refcount.
                    *peer_topics.entry(topic).or_insert(0) += 1;
                } else {
                    decrement_topic(peer_topics, topic)?;
                    if peer_topics.is_empty() {
                        self.subscriptions.remove(&peer);
                    }
                }
                Ok(())
            }
            PeerEvent::HandshakeComplete { .. } | PeerEvent::Message(_) => Ok(()),
        }
    }

    pub fn publish(&self, message: Multipart) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        if message.is_empty() {
            return Err(ProtocolError::EmptyMessage);
        }

        let first_frame = &message[0];
        let mut out = Vec::new();
        for (peer, topics) in &self.subscriptions {
            // PUB/SUB matching is prefix-based on the first frame only.
            if topics
                .keys()
                .any(|topic| topic.is_empty() || first_frame.starts_with(topic))
            {
                out.push(PatternAction::Send {
                    peer: *peer,
                    item: OutboundItem::Message(message.clone()),
                });
            }
        }

        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub struct SubCore<PeerId> {
    peers: Vec<PeerId>,
    subscriptions: HashMap<Bytes, usize>,
    filter_inbound: bool,
}

impl<PeerId> Default for SubCore<PeerId> {
    fn default() -> Self {
        Self {
            peers: Vec::new(),
            subscriptions: HashMap::new(),
            filter_inbound: true,
        }
    }
}

impl<PeerId> SubCore<PeerId>
where
    PeerId: Copy + Eq,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_filter_inbound(mut self, filter_inbound: bool) -> Self {
        self.filter_inbound = filter_inbound;
        self
    }

    pub fn add_peer(&mut self, peer: PeerId) -> Vec<PatternAction<PeerId>> {
        if self.peers.contains(&peer) {
            return Vec::new();
        }

        self.peers.push(peer);
        // New connections need the full local subscription set replayed to them.
        self.subscriptions
            .keys()
            .cloned()
            .map(|topic| PatternAction::Send {
                peer,
                item: OutboundItem::Subscribe(topic),
            })
            .collect()
    }

    pub fn remove_peer(&mut self, peer: PeerId) {
        self.peers.retain(|candidate| *candidate != peer);
    }

    pub fn subscribe(&mut self, topic: Bytes) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        // Refcounts keep repeated subscribe calls balanced with cancel.
        *self.subscriptions.entry(topic.clone()).or_insert(0) += 1;
        Ok(self
            .peers
            .iter()
            .copied()
            .map(|peer| PatternAction::Send {
                peer,
                item: OutboundItem::Subscribe(topic.clone()),
            })
            .collect())
    }

    pub fn cancel(&mut self, topic: Bytes) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        decrement_topic(&mut self.subscriptions, topic.clone())?;
        Ok(self
            .peers
            .iter()
            .copied()
            .map(|peer| PatternAction::Send {
                peer,
                item: OutboundItem::Cancel(topic.clone()),
            })
            .collect())
    }

    pub fn on_peer_event(
        &mut self,
        peer: PeerId,
        event: PeerEvent,
    ) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        match event {
            PeerEvent::Message(message) => {
                if message.is_empty() {
                    return Err(ProtocolError::EmptyMessage);
                }

                // Local filtering mirrors SUB semantics when the remote side forwards everything.
                if self.filter_inbound
                    && !self
                        .subscriptions
                        .keys()
                        .any(|topic| topic.is_empty() || message[0].starts_with(topic))
                {
                    return Ok(Vec::new());
                }

                Ok(vec![PatternAction::Deliver { peer, message }])
            }
            PeerEvent::HandshakeComplete { .. } | PeerEvent::Subscription { .. } => Ok(Vec::new()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReqCore<PeerId> {
    peers: VecDeque<PeerId>,
    waiting_on: Option<PeerId>,
}

impl<PeerId> Default for ReqCore<PeerId> {
    fn default() -> Self {
        Self {
            peers: VecDeque::new(),
            waiting_on: None,
        }
    }
}

impl<PeerId> ReqCore<PeerId>
where
    PeerId: Copy + Eq,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_peer(&mut self, peer: PeerId) {
        if !self.peers.contains(&peer) {
            self.peers.push_back(peer);
        }
    }

    pub fn remove_peer(&mut self, peer: PeerId) {
        self.peers.retain(|candidate| *candidate != peer);
        if self.waiting_on == Some(peer) {
            self.waiting_on = None;
        }
    }

    pub fn send(&mut self, message: Multipart) -> Result<PatternAction<PeerId>, ProtocolError> {
        if message.is_empty() {
            return Err(ProtocolError::EmptyMessage);
        }
        if self.waiting_on.is_some() {
            return Err(ProtocolError::ReqStateViolation(
                "cannot send a new request before receiving the reply",
            ));
        }

        let peer = self
            .peers
            .pop_front()
            .ok_or(ProtocolError::NoAvailablePeers)?;
        self.peers.push_back(peer);
        self.waiting_on = Some(peer);

        let mut wire_message = Vec::with_capacity(message.len() + 1);
        // REQ prefixes the body with the empty delimiter frame REP expects.
        wire_message.push(Bytes::new());
        wire_message.extend(message);

        Ok(PatternAction::Send {
            peer,
            item: OutboundItem::Message(wire_message),
        })
    }

    pub fn on_peer_event(
        &mut self,
        peer: PeerId,
        event: PeerEvent,
    ) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        match event {
            PeerEvent::Message(mut message) => {
                // Ignore stray replies from peers we are not currently waiting on.
                if self.waiting_on != Some(peer) {
                    return Ok(Vec::new());
                }
                if message.is_empty() || !message[0].is_empty() {
                    return Err(ProtocolError::MissingEnvelopeDelimiter);
                }

                message.remove(0);
                if message.is_empty() {
                    return Err(ProtocolError::MissingBodyFrames);
                }

                self.waiting_on = None;
                Ok(vec![PatternAction::Deliver { peer, message }])
            }
            PeerEvent::HandshakeComplete { .. } | PeerEvent::Subscription { .. } => Ok(Vec::new()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueuedRequest {
    envelope: Multipart,
    body: Multipart,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveReply<PeerId> {
    peer: PeerId,
    envelope: Multipart,
}

#[derive(Debug, Clone)]
pub struct RepCore<PeerId> {
    queues: HashMap<PeerId, VecDeque<QueuedRequest>>,
    ready_peers: VecDeque<PeerId>,
    active: Option<ActiveReply<PeerId>>,
}

impl<PeerId> Default for RepCore<PeerId> {
    fn default() -> Self {
        Self {
            queues: HashMap::new(),
            ready_peers: VecDeque::new(),
            active: None,
        }
    }
}

impl<PeerId> RepCore<PeerId>
where
    PeerId: Copy + Eq + Hash,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_peer(&mut self, peer: PeerId) {
        self.queues.entry(peer).or_default();
    }

    pub fn remove_peer(
        &mut self,
        peer: PeerId,
    ) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        self.queues.remove(&peer);
        self.ready_peers.retain(|candidate| *candidate != peer);
        if self.active.as_ref().map(|active| active.peer) == Some(peer) {
            self.active = None;
            return self.dispatch_next();
        }
        Ok(Vec::new())
    }

    pub fn on_peer_event(
        &mut self,
        peer: PeerId,
        event: PeerEvent,
    ) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        match event {
            PeerEvent::Message(message) => {
                let (envelope, body) = split_envelope(message)?;
                // Keep each peer's requests ordered even when peers interleave.
                let queue = self.queues.entry(peer).or_default();
                let was_empty = queue.is_empty();
                queue.push_back(QueuedRequest { envelope, body });
                // A peer only enters the ready queue when it transitions from empty to non-empty.
                if was_empty && self.active.as_ref().map(|active| active.peer) != Some(peer) {
                    self.ready_peers.push_back(peer);
                }
                if self.active.is_none() {
                    return self.dispatch_next();
                }
                Ok(Vec::new())
            }
            PeerEvent::HandshakeComplete { .. } | PeerEvent::Subscription { .. } => Ok(Vec::new()),
        }
    }

    pub fn reply(
        &mut self,
        message: Multipart,
    ) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        if message.is_empty() {
            return Err(ProtocolError::EmptyMessage);
        }
        let Some(active) = self.active.take() else {
            return Err(ProtocolError::RepStateViolation(
                "cannot send a reply before receiving a request",
            ));
        };

        if self
            .queues
            .get(&active.peer)
            .is_some_and(|queue| !queue.is_empty())
        {
            self.ready_peers.push_back(active.peer);
        }

        let mut wire_message = active.envelope;
        wire_message.extend(message);

        let mut out = vec![PatternAction::Send {
            peer: active.peer,
            item: OutboundItem::Message(wire_message),
        }];
        out.extend(self.dispatch_next()?);
        Ok(out)
    }

    fn dispatch_next(&mut self) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        let Some(peer) = self.ready_peers.pop_front() else {
            return Ok(Vec::new());
        };

        let queue = self
            .queues
            .get_mut(&peer)
            .expect("ready peer must have an existing queue");
        let request = queue
            .pop_front()
            .expect("ready peer queue must be non-empty");

        self.active = Some(ActiveReply {
            peer,
            envelope: request.envelope,
        });

        // REP exposes one active request at a time until reply() consumes it.
        Ok(vec![PatternAction::Deliver {
            peer,
            message: request.body,
        }])
    }
}

fn decrement_topic(topics: &mut HashMap<Bytes, usize>, topic: Bytes) -> Result<(), ProtocolError> {
    match topics.get_mut(&topic) {
        Some(count) if *count > 1 => {
            *count -= 1;
            Ok(())
        }
        Some(_) => {
            topics.remove(&topic);
            Ok(())
        }
        None => Err(ProtocolError::UnknownSubscription),
    }
}

fn split_envelope(message: Multipart) -> Result<(Multipart, Multipart), ProtocolError> {
    let Some(delimiter_index) = message.iter().position(|frame| frame.is_empty()) else {
        return Err(ProtocolError::MissingEnvelopeDelimiter);
    };

    let (envelope, body) = message.split_at(delimiter_index + 1);
    if body.is_empty() {
        return Err(ProtocolError::MissingBodyFrames);
    }

    Ok((envelope.to_vec(), body.to_vec()))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{PatternAction, PubCore, RepCore, ReqCore, SubCore};
    use crate::{OutboundItem, PeerEvent, ProtocolError};

    #[test]
    fn pubcore_tracks_additive_subscriptions() {
        let mut core = PubCore::<u8>::new();
        core.on_peer_event(
            1,
            PeerEvent::Subscription {
                subscribe: true,
                topic: Bytes::from_static(b"ab"),
            },
        )
        .unwrap();
        core.on_peer_event(
            1,
            PeerEvent::Subscription {
                subscribe: true,
                topic: Bytes::from_static(b"ab"),
            },
        )
        .unwrap();
        core.on_peer_event(
            1,
            PeerEvent::Subscription {
                subscribe: false,
                topic: Bytes::from_static(b"ab"),
            },
        )
        .unwrap();

        let actions = core
            .publish(vec![
                Bytes::from_static(b"abc"),
                Bytes::from_static(b"body"),
            ])
            .unwrap();
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn pubcore_empty_subscription_matches_all() {
        let mut core = PubCore::<u8>::new();
        core.on_peer_event(
            7,
            PeerEvent::Subscription {
                subscribe: true,
                topic: Bytes::new(),
            },
        )
        .unwrap();

        let actions = core.publish(vec![Bytes::from_static(b"topic")]).unwrap();
        assert_eq!(
            actions,
            vec![PatternAction::Send {
                peer: 7,
                item: OutboundItem::Message(vec![Bytes::from_static(b"topic")]),
            }]
        );
    }

    #[test]
    fn subcore_replays_subscriptions_to_new_peers() {
        let mut core = SubCore::<u8>::new();
        let _ = core.subscribe(Bytes::from_static(b"alpha")).unwrap();
        let actions = core.add_peer(3);
        assert_eq!(
            actions,
            vec![PatternAction::Send {
                peer: 3,
                item: OutboundItem::Subscribe(Bytes::from_static(b"alpha")),
            }]
        );
    }

    #[test]
    fn subcore_filters_inbound_messages() {
        let mut core = SubCore::<u8>::new();
        core.add_peer(1);
        let _ = core.subscribe(Bytes::from_static(b"ab")).unwrap();

        let allowed = core
            .on_peer_event(1, PeerEvent::Message(vec![Bytes::from_static(b"abc")]))
            .unwrap();
        assert_eq!(
            allowed,
            vec![PatternAction::Deliver {
                peer: 1,
                message: vec![Bytes::from_static(b"abc")],
            }]
        );

        let blocked = core
            .on_peer_event(1, PeerEvent::Message(vec![Bytes::from_static(b"zzz")]))
            .unwrap();
        assert!(blocked.is_empty());
    }

    #[test]
    fn reqcore_inserts_delimiter_and_enforces_last_peer() {
        let mut core = ReqCore::<u8>::new();
        core.add_peer(1);
        core.add_peer(2);

        let first = core.send(vec![Bytes::from_static(b"one")]).unwrap();
        assert_eq!(
            first,
            PatternAction::Send {
                peer: 1,
                item: OutboundItem::Message(vec![Bytes::new(), Bytes::from_static(b"one")]),
            }
        );

        let ignored = core
            .on_peer_event(
                2,
                PeerEvent::Message(vec![Bytes::new(), Bytes::from_static(b"wrong")]),
            )
            .unwrap();
        assert!(ignored.is_empty());

        let delivered = core
            .on_peer_event(
                1,
                PeerEvent::Message(vec![Bytes::new(), Bytes::from_static(b"reply")]),
            )
            .unwrap();
        assert_eq!(
            delivered,
            vec![PatternAction::Deliver {
                peer: 1,
                message: vec![Bytes::from_static(b"reply")],
            }]
        );
    }

    #[test]
    fn reqcore_round_robins_requests() {
        let mut core = ReqCore::<u8>::new();
        core.add_peer(1);
        core.add_peer(2);

        let first = core.send(vec![Bytes::from_static(b"one")]).unwrap();
        let _ = core
            .on_peer_event(
                1,
                PeerEvent::Message(vec![Bytes::new(), Bytes::from_static(b"ok")]),
            )
            .unwrap();
        let second = core.send(vec![Bytes::from_static(b"two")]).unwrap();

        assert_eq!(
            first,
            PatternAction::Send {
                peer: 1,
                item: OutboundItem::Message(vec![Bytes::new(), Bytes::from_static(b"one")]),
            }
        );
        assert_eq!(
            second,
            PatternAction::Send {
                peer: 2,
                item: OutboundItem::Message(vec![Bytes::new(), Bytes::from_static(b"two")]),
            }
        );
    }

    #[test]
    fn reqcore_rejects_strict_alternation_violations() {
        let mut core = ReqCore::<u8>::new();
        core.add_peer(1);
        let _ = core.send(vec![Bytes::from_static(b"one")]).unwrap();

        assert_eq!(
            core.send(vec![Bytes::from_static(b"two")]).unwrap_err(),
            ProtocolError::ReqStateViolation(
                "cannot send a new request before receiving the reply",
            )
        );
    }

    #[test]
    fn repcore_restores_envelope_on_reply() {
        let mut core = RepCore::<u8>::new();
        core.add_peer(9);

        let delivered = core
            .on_peer_event(
                9,
                PeerEvent::Message(vec![
                    Bytes::from_static(b"route"),
                    Bytes::new(),
                    Bytes::from_static(b"body"),
                ]),
            )
            .unwrap();
        assert_eq!(
            delivered,
            vec![PatternAction::Deliver {
                peer: 9,
                message: vec![Bytes::from_static(b"body")],
            }]
        );

        let replied = core.reply(vec![Bytes::from_static(b"ok")]).unwrap();
        assert_eq!(
            replied,
            vec![PatternAction::Send {
                peer: 9,
                item: OutboundItem::Message(vec![
                    Bytes::from_static(b"route"),
                    Bytes::new(),
                    Bytes::from_static(b"ok"),
                ]),
            }]
        );
    }

    #[test]
    fn repcore_fair_queues_across_peers() {
        let mut core = RepCore::<u8>::new();
        core.add_peer(1);
        core.add_peer(2);

        let first = core
            .on_peer_event(
                1,
                PeerEvent::Message(vec![Bytes::new(), Bytes::from_static(b"one")]),
            )
            .unwrap();
        assert_eq!(
            first,
            vec![PatternAction::Deliver {
                peer: 1,
                message: vec![Bytes::from_static(b"one")],
            }]
        );

        let none = core
            .on_peer_event(
                1,
                PeerEvent::Message(vec![Bytes::new(), Bytes::from_static(b"two")]),
            )
            .unwrap();
        assert!(none.is_empty());

        let none = core
            .on_peer_event(
                2,
                PeerEvent::Message(vec![Bytes::new(), Bytes::from_static(b"three")]),
            )
            .unwrap();
        assert!(none.is_empty());

        let after_reply = core.reply(vec![Bytes::from_static(b"ok")]).unwrap();
        assert_eq!(
            after_reply[1],
            PatternAction::Deliver {
                peer: 2,
                message: vec![Bytes::from_static(b"three")],
            }
        );
    }
}
