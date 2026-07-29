//! Carrying Ultraviolet payments over the real Signal Protocol.
//!
//! **What this is.** Signal's own `libsignal` — the crate Signal Messenger
//! builds its clients on, taken from `signalapp/libsignal` at a release tag, not
//! a same-named reimplementation on crates.io. Two participants establish a
//! genuine session (PQXDH, then the Double Ratchet), and an Ultraviolet payment
//! rides it as an ordinary message payload.
//!
//! **What this is not.** It is not the Signal *network*. Signal blocks
//! third-party clients, so a real deployment means running your own server. The
//! [`Relay`] here stands in for that server, and it is deliberately stupid: it
//! stores opaque envelopes addressed to opaque recipients and can describe
//! exactly what it saw, which is the point of the exercise.
//!
//! ## Two layers of encryption, and why both
//!
//! A payment is sealed twice, by different schemes, for different reasons.
//!
//! 1. **Ultraviolet's own envelope** (`uv_envelope`): hybrid ML-KEM-768 +
//!    X25519, addressed to the payee's scan key. This is what makes the payment
//!    confidential *from the carrier*, and it does not care who the carrier is.
//!    It would be there if the bundle travelled by email.
//! 2. **Signal's session**: PQXDH and the Double Ratchet, addressed to the
//!    payee's device. This makes the traffic look like every other Signal
//!    message, and it brings forward secrecy the envelope does not have.
//!
//! Neither is redundant. Strip the Signal layer and the carrier learns who is
//! talking to whom and when. Strip the envelope and the server operator — who
//! terminates nothing, but does route — becomes someone you must trust not to be
//! the payee's peer. The rule from spec/05 stands: **the money path never
//! inherits confidentiality from the transport.**
//!
//! Both layers are independently post-quantum — Signal's handshake uses Kyber
//! pre-keys, ours uses ML-KEM-768 — and neither is on the money path, so a break
//! in either costs privacy and never funds.
//!
//! ## A licensing note, because a manifest cannot override someone else's licence
//!
//! This crate is declared MIT like the rest of the workspace, and that covers
//! the code in this directory. It does not, and cannot, cover `libsignal`, which
//! is AGPL-3.0. **Anyone who distributes a binary built from this crate, or runs
//! one as a network service, inherits AGPL obligations** — source availability
//! for the whole combined work — whatever `Cargo.toml` says here. Nothing in
//! this project is released, so nothing has been triggered. If that changes,
//! this is the crate to think about first.

use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::TryRngCore as _;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// What a carrier is allowed to see, recorded so the claim can be checked
/// rather than asserted.
#[derive(Clone, Debug)]
pub struct Carried {
    /// The mailbox the envelope was left in.
    pub to: String,
    /// The opaque bytes. The relay never parses these.
    pub bytes: Vec<u8>,
}

/// A stand-in for a Signal server: store and forward, and nothing else.
///
/// Deliberately not a Signal server. It exists to be inspected — see
/// [`Relay::what_it_saw`] — because "the carrier learns nothing" is a claim that
/// ought to be testable rather than asserted.
#[derive(Clone, Default)]
pub struct Relay {
    inboxes: Arc<Mutex<HashMap<String, Vec<Carried>>>>,
    log: Arc<Mutex<Vec<Carried>>>,
}

impl Relay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept an envelope for a recipient. The relay cannot read it, and does
    /// not try.
    pub fn deliver(&self, to: &str, bytes: Vec<u8>) {
        let item = Carried {
            to: to.to_owned(),
            bytes,
        };
        self.log.lock().expect("relay log").push(item.clone());
        self.inboxes
            .lock()
            .expect("relay inboxes")
            .entry(to.to_owned())
            .or_default()
            .push(item);
    }

    /// Collect anything waiting for `who`.
    pub fn collect(&self, who: &str) -> Vec<Carried> {
        self.inboxes
            .lock()
            .expect("relay inboxes")
            .remove(who)
            .unwrap_or_default()
    }

    /// Everything that has ever passed through, for inspection by a test.
    pub fn what_it_saw(&self) -> Vec<Carried> {
        self.log.lock().expect("relay log").clone()
    }
}

/// One participant: a Signal identity, its key store, and its address.
pub struct Participant {
    pub address: ProtocolAddress,
    store: InMemSignalProtocolStore,
}

impl Participant {
    /// Create an identity and publish one of each kind of pre-key.
    ///
    /// The Kyber pre-key is what makes the handshake PQXDH rather than X3DH,
    /// and it is not optional here: a payment protocol whose whole premise is
    /// post-quantum should not ride a classical-only handshake.
    pub async fn new(name: &str) -> Result<Self, SignalProtocolError> {
        let mut rng = OsRng.unwrap_err();
        let identity = IdentityKeyPair::generate(&mut rng);
        // Registration IDs are 14 bits.
        let registration_id: u32 = u32::from(rand::Rng::random::<u8>(&mut rng));
        let mut store = InMemSignalProtocolStore::new(identity, registration_id)?;

        let pre_key = KeyPair::generate(&mut rng);
        store
            .save_pre_key(1u32.into(), &PreKeyRecord::new(1u32.into(), &pre_key))
            .await?;

        let signed = KeyPair::generate(&mut rng);
        let signed_sig = identity
            .private_key()
            .calculate_signature(&signed.public_key.serialize(), &mut rng)?;
        store
            .save_signed_pre_key(
                1u32.into(),
                &SignedPreKeyRecord::new(
                    1u32.into(),
                    Timestamp::from_epoch_millis(0),
                    &signed,
                    &signed_sig,
                ),
            )
            .await?;

        let kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
        let kyber_sig = identity
            .private_key()
            .calculate_signature(&kyber.public_key.serialize(), &mut rng)?;
        store
            .save_kyber_pre_key(
                1u32.into(),
                &KyberPreKeyRecord::new(
                    1u32.into(),
                    Timestamp::from_epoch_millis(0),
                    &kyber,
                    &kyber_sig,
                ),
            )
            .await?;

        Ok(Self {
            address: ProtocolAddress::new(name.to_owned(), DeviceId::new(1).expect("device 1")),
            store,
        })
    }

    /// The bundle a peer needs to start talking to this participant.
    ///
    /// In a real deployment the server holds these so a sender can begin while
    /// the recipient is offline. That asynchrony is exactly why Ultraviolet's
    /// own addresses are batches of one-time slots: same problem, same shape of
    /// answer, arrived at independently.
    pub async fn pre_key_bundle(&self) -> Result<PreKeyBundle, SignalProtocolError> {
        let identity = self.store.get_identity_key_pair().await?;
        let registration_id = self.store.get_local_registration_id().await?;
        let pre = self.store.get_pre_key(1u32.into()).await?;
        let signed = self.store.get_signed_pre_key(1u32.into()).await?;
        let kyber = self.store.get_kyber_pre_key(1u32.into()).await?;

        PreKeyBundle::new(
            registration_id,
            DeviceId::new(1).expect("device 1"),
            Some((pre.id()?, pre.public_key()?)),
            signed.id()?,
            signed.public_key()?,
            signed.signature()?,
            kyber.id()?,
            kyber.public_key()?,
            kyber.signature()?,
            *identity.identity_key(),
        )
    }

    /// Start a session with `peer` from their published bundle — the PQXDH half
    /// of the handshake.
    pub async fn start_session(
        &mut self,
        peer: &ProtocolAddress,
        bundle: &PreKeyBundle,
    ) -> Result<(), SignalProtocolError> {
        let mut rng = OsRng.unwrap_err();
        process_prekey_bundle(
            peer,
            &self.address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            bundle,
            SystemTime::now(),
            &mut rng,
        )
        .await
    }

    /// Encrypt `payload` to `peer` and hand it to the relay.
    ///
    /// `payload` is already sealed by `uv_envelope`. This layer does not know,
    /// and must not need to know, that it is carrying money.
    pub async fn send(
        &mut self,
        relay: &Relay,
        peer: &ProtocolAddress,
        payload: &[u8],
    ) -> Result<(), SignalProtocolError> {
        let mut rng = OsRng.unwrap_err();
        let ciphertext = message_encrypt(
            payload,
            peer,
            &self.address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .await?;
        relay.deliver(peer.name(), ciphertext.serialize().to_vec());
        Ok(())
    }

    /// Collect and decrypt everything waiting, returning the payloads.
    pub async fn receive(
        &mut self,
        relay: &Relay,
        from: &ProtocolAddress,
    ) -> Result<Vec<Vec<u8>>, SignalProtocolError> {
        let mut rng = OsRng.unwrap_err();
        let mut out = Vec::new();
        for item in relay.collect(self.address.name()) {
            // A first message arrives as a PreKeySignalMessage: it carries the
            // material the recipient needs to finish the handshake, which is
            // what lets a sender start while the recipient is offline.
            let msg = match PreKeySignalMessage::try_from(item.bytes.as_slice()) {
                Ok(m) => CiphertextMessage::PreKeySignalMessage(m),
                Err(_) => CiphertextMessage::SignalMessage(SignalMessage::try_from(
                    item.bytes.as_slice(),
                )?),
            };
            out.push(
                message_decrypt(
                    &msg,
                    from,
                    &self.address,
                    &mut self.store.session_store,
                    &mut self.store.identity_store,
                    &mut self.store.pre_key_store,
                    &self.store.signed_pre_key_store,
                    &mut self.store.kyber_pre_key_store,
                    &mut rng,
                )
                .await?,
            );
        }
        Ok(out)
    }
}
