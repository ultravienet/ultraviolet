//! Owned notes and the wallet's note store.
//!
//! A note we own carries, besides the kernel [`Note`] itself, the proof and
//! hop-output that *created* it — because spending it means chaining a new
//! recursive proof on top of that one (spec/04-PROOFS). Proof bytes are opaque
//! here (SP1 lives in `uv-prove`), keeping this crate SP1-free.

use serde::{Deserialize, Serialize};

use ultraviolet_kernel::note::Note;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnedNote {
    pub note: Note,
    /// The compressed recursive proof attesting this note's full history.
    pub proof_bytes: Vec<u8>,
    /// `HopOutput::encode()` of the hop that created this note.
    pub hop_output_bytes: Vec<u8>,
    pub spent: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NoteStore {
    pub notes: Vec<OwnedNote>,
}

impl NoteStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, note: OwnedNote) {
        self.notes.push(note);
    }

    pub fn balance(&self) -> u64 {
        self.notes.iter().filter(|n| !n.spent).map(|n| n.note.value).sum()
    }

    /// Find one unspent note that covers `amount` exactly-or-more (single-input
    /// coin selection; multi-input is a later refinement — see spec/99).
    /// Returns the store index.
    pub fn find_spendable(&self, amount: u64) -> Option<usize> {
        // Smallest covering note, to keep change small.
        self.notes
            .iter()
            .enumerate()
            .filter(|(_, n)| !n.spent && n.note.value >= amount)
            .min_by_key(|(_, n)| n.note.value)
            .map(|(i, _)| i)
    }

    /// Find the smallest *already-spent* note covering `amount` — used only to
    /// stage the double-spend demo (re-spending a note the chain already saw).
    pub fn find_spent_spendable(&self, amount: u64) -> Option<usize> {
        self.notes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.spent && n.note.value >= amount)
            .min_by_key(|(_, n)| n.note.value)
            .map(|(i, _)| i)
    }

    pub fn mark_spent(&mut self, index: usize) {
        if let Some(n) = self.notes.get_mut(index) {
            n.spent = true;
        }
    }

    pub fn unspent(&self) -> impl Iterator<Item = &OwnedNote> {
        self.notes.iter().filter(|n| !n.spent)
    }
}
