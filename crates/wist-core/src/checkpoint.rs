use crate::crypto::{hex_encode, verify_bytes, PublicKey, SigningKey};
use crate::error::Error;
use crate::merkle;
use crate::timestamp::log_seconds;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const AGGREGATOR_KEY_TYPE: u8 = 0x01;
pub const WITNESS_KEY_TYPE: u8 = 0x04;
pub const MAX_SIGNATURE_LINES: usize = 16;

const SIGNATURE_PREFIX: &str = "\u{2014} ";

fn invalid(message: &str) -> Error {
    Error::Checkpoint(format!("WIST3-E03 {message}"))
}

fn divergence(message: &str) -> Error {
    Error::Checkpoint(format!("WIST3-E02 {message}"))
}

pub fn absent_checkpoint(epoch_number: u64) -> Error {
    Error::Checkpoint(format!(
        "WIST3-E01 no source serves the archived Checkpoint of Epoch {epoch_number}"
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureLine {
    pub name: String,
    pub key_id: [u8; 4],
    pub signature: Vec<u8>,
}

impl SignatureLine {
    pub fn encode(&self) -> String {
        let mut blob = self.key_id.to_vec();
        blob.extend_from_slice(&self.signature);
        format!("{SIGNATURE_PREFIX}{} {}", self.name, STANDARD.encode(&blob))
    }

    pub fn parse(line: &str) -> Result<Self, Error> {
        let rest = line
            .strip_prefix(SIGNATURE_PREFIX)
            .ok_or_else(|| invalid("signature line without the em-dash-space prefix"))?;
        let (name, encoded) = rest
            .rsplit_once(' ')
            .ok_or_else(|| invalid("signature line without a signature value"))?;
        if name.is_empty() {
            return Err(invalid("signature line with an empty key name"));
        }
        if name.contains('+') || name.chars().any(char::is_whitespace) {
            return Err(invalid(
                "signature line whose key name carries a plus or a White_Space character",
            ));
        }
        let blob = STANDARD
            .decode(encoded)
            .map_err(|_| invalid("signature value is not base64"))?;
        if STANDARD.encode(&blob) != encoded {
            return Err(invalid("signature value is not canonical base64"));
        }
        if blob.len() < 5 {
            return Err(invalid(
                "signature value is shorter than a key ID and a signature",
            ));
        }
        Ok(SignatureLine {
            name: name.to_owned(),
            key_id: blob[..4].try_into().expect("four octets"),
            signature: blob[4..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    origin: String,
    tree_size: u64,
    root: [u8; 32],
    epoch_number: u64,
    sealed_at: String,
    signatures: Vec<SignatureLine>,
}

impl Checkpoint {
    pub fn new(
        origin: &str,
        tree_size: u64,
        root: [u8; 32],
        epoch_number: u64,
        sealed_at: &str,
    ) -> Result<Self, Error> {
        if origin.is_empty() || origin.contains('\n') {
            return Err(invalid("the origin is not one line of text"));
        }
        log_seconds(sealed_at)?;
        Ok(Checkpoint {
            origin: origin.to_owned(),
            tree_size,
            root,
            epoch_number,
            sealed_at: sealed_at.to_owned(),
            signatures: Vec::new(),
        })
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }

    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    pub fn root_token(&self) -> String {
        format!("sha256:{}", hex_encode(&self.root))
    }

    pub fn epoch_number(&self) -> u64 {
        self.epoch_number
    }

    pub fn sealed_at(&self) -> &str {
        &self.sealed_at
    }

    pub fn sealed_at_s(&self) -> Result<i64, Error> {
        log_seconds(&self.sealed_at)
    }

    pub fn signatures(&self) -> &[SignatureLine] {
        &self.signatures
    }

    pub fn note_text(&self) -> String {
        format!(
            "{}\n{}\n{}\nepoch_number {}\nsealed_at {}\n",
            self.origin,
            self.tree_size,
            STANDARD.encode(self.root),
            self.epoch_number,
            self.sealed_at
        )
    }

    pub fn encode(&self) -> String {
        let mut note = self.note_text();
        note.push('\n');
        for line in &self.signatures {
            note.push_str(&line.encode());
            note.push('\n');
        }
        note
    }

    pub fn parse(note: &str) -> Result<Self, Error> {
        let (text, block) = note
            .split_once("\n\n")
            .ok_or_else(|| invalid("no blank line between the note text and its signatures"))?;
        let lines: Vec<&str> = text.split('\n').collect();
        if lines.len() != 5 {
            return Err(invalid("the note text is not five lines"));
        }
        let tree_size = parse_decimal(lines[1])
            .ok_or_else(|| invalid("the tree size is not a canonical decimal"))?;
        let root = STANDARD
            .decode(lines[2])
            .map_err(|_| invalid("the root hash is not base64"))?;
        if STANDARD.encode(&root) != lines[2] {
            return Err(invalid("the root hash is not canonical base64"));
        }
        let root: [u8; 32] = root
            .try_into()
            .map_err(|_| invalid("the root hash is not 32 octets"))?;
        let epoch_number = lines[3]
            .strip_prefix("epoch_number ")
            .and_then(parse_decimal)
            .ok_or_else(|| invalid("malformed epoch_number line"))?;
        let sealed_at = lines[4]
            .strip_prefix("sealed_at ")
            .ok_or_else(|| invalid("malformed sealed_at line"))?;
        log_seconds(sealed_at).map_err(|_| invalid("sealed_at is outside the §3.1 profile"))?;

        let mut signature_lines: Vec<&str> = block.split('\n').collect();
        if signature_lines.last() == Some(&"") {
            signature_lines.pop();
        } else {
            return Err(invalid("the note does not end with a newline"));
        }
        if signature_lines.is_empty() {
            return Err(invalid("the note carries no signature line"));
        }
        if signature_lines.len() > MAX_SIGNATURE_LINES {
            return Err(invalid(
                "the note carries more signature lines than the sixteen §5 admits",
            ));
        }
        let signatures = signature_lines
            .iter()
            .map(|line| SignatureLine::parse(line))
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(Checkpoint {
            origin: lines[0].to_owned(),
            tree_size,
            root,
            epoch_number,
            sealed_at: sealed_at.to_owned(),
            signatures,
        })
    }

    pub fn sign(&mut self, key: &SigningKey) {
        let line = aggregator_signature_line(&self.origin, key, &self.note_text());
        self.signatures.push(line);
    }

    pub fn add_signature(&mut self, line: SignatureLine) {
        self.signatures.push(line);
    }

    pub fn verify_inclusion(
        &self,
        leaf: &[u8; 32],
        index: u64,
        tree_size: u64,
        path: &[[u8; 32]],
    ) -> Result<(), Error> {
        if tree_size != self.tree_size {
            return Err(Error::Merkle(
                "the proof's tree size is not the Checkpoint's".into(),
            ));
        }
        merkle::verify_inclusion(leaf, index, tree_size, path, &self.root)
    }
}

fn parse_decimal(value: &str) -> Option<u64> {
    let canonical = value == "0" || (!value.starts_with('0') && !value.is_empty());
    let digits = value.bytes().all(|b| b.is_ascii_digit());
    (canonical && digits).then(|| value.parse().ok())?
}

pub fn note_key_id(name: &str, key_type: u8, public_key: &[u8; 32]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update([0x0A, key_type]);
    hasher.update(public_key);
    let digest = hasher.finalize();
    digest[..4].try_into().expect("four octets")
}

pub fn aggregator_key_id(log_id: &str, public_key: &PublicKey) -> [u8; 4] {
    note_key_id(log_id, AGGREGATOR_KEY_TYPE, &public_key.to_bytes())
}

pub fn witness_key_id(name: &str, public_key: &PublicKey) -> [u8; 4] {
    note_key_id(name, WITNESS_KEY_TYPE, &public_key.to_bytes())
}

pub fn verifier_key(log_id: &str, public_key: &PublicKey) -> String {
    let mut encoded = vec![AGGREGATOR_KEY_TYPE];
    encoded.extend_from_slice(&public_key.to_bytes());
    format!(
        "{log_id}+{}+{}",
        hex_encode(&aggregator_key_id(log_id, public_key)),
        STANDARD.encode(&encoded)
    )
}

pub fn aggregator_signature_line(log_id: &str, key: &SigningKey, note_text: &str) -> SignatureLine {
    SignatureLine {
        name: log_id.to_owned(),
        key_id: aggregator_key_id(log_id, &key.public()),
        signature: key.sign_bytes(note_text.as_bytes()).to_vec(),
    }
}

pub fn cosignature_message(note_text: &str, timestamp_s: u64) -> Vec<u8> {
    let mut message = format!("cosignature/v1\ntime {timestamp_s}\n").into_bytes();
    message.extend_from_slice(note_text.as_bytes());
    message
}

pub fn cosignature_line(
    name: &str,
    key: &SigningKey,
    note_text: &str,
    timestamp_s: u64,
) -> SignatureLine {
    let message = cosignature_message(note_text, timestamp_s);
    let mut signature = timestamp_s.to_be_bytes().to_vec();
    signature.extend_from_slice(&key.sign_bytes(&message));
    SignatureLine {
        name: name.to_owned(),
        key_id: witness_key_id(name, &key.public()),
        signature,
    }
}

#[derive(Debug, Clone)]
pub struct AggregatorKey {
    pub key_id: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone)]
pub struct WitnessKey {
    pub name: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verification {
    pub signers: BTreeSet<String>,
    pub cosigners: BTreeSet<String>,
}

pub fn verify(
    checkpoint: &Checkpoint,
    log_id: &str,
    aggregator_keys: &[AggregatorKey],
    witnesses: &[WitnessKey],
) -> Result<Verification, Error> {
    if checkpoint.origin() != log_id {
        return Err(invalid("the origin is not the Log's log_id"));
    }
    let note_text = checkpoint.note_text();
    let mut verification = Verification::default();
    for line in checkpoint.signatures() {
        if let Some(key) = aggregator_keys.iter().find(|key| {
            line.name == log_id && aggregator_key_id(log_id, &key.public_key) == line.key_id
        }) {
            let signature: [u8; 64] = line
                .signature
                .clone()
                .try_into()
                .map_err(|_| invalid("an Aggregator signature is not 64 octets"))?;
            verify_bytes(&key.public_key, note_text.as_bytes(), &signature)
                .map_err(|_| invalid("a signature under a known key does not verify"))?;
            verification.signers.insert(key.key_id.clone());
            continue;
        }
        if let Some(witness) = witnesses
            .iter()
            .find(|w| line.name == w.name && witness_key_id(&w.name, &w.public_key) == line.key_id)
        {
            verify_cosignature(&witness.public_key, &note_text, &line.signature).map_err(|_| {
                invalid("a Cosignature under a trusted Witness key does not verify")
            })?;
            verification.cosigners.insert(witness.name.clone());
        }
    }
    if verification.signers.is_empty() {
        return Err(invalid(
            "no signature under an Aggregator key valid at this height",
        ));
    }
    Ok(verification)
}

pub fn verify_cosignature(
    public_key: &PublicKey,
    note_text: &str,
    after_key_id: &[u8],
) -> Result<u64, Error> {
    if after_key_id.len() != 72 {
        return Err(invalid(
            "a Cosignature is not a timestamp and a 64-octet signature",
        ));
    }
    let timestamp = u64::from_be_bytes(after_key_id[..8].try_into().expect("eight octets"));
    let signature: [u8; 64] = after_key_id[8..].try_into().expect("64 octets");
    verify_bytes(
        public_key,
        &cosignature_message(note_text, timestamp),
        &signature,
    )?;
    Ok(timestamp)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adoption {
    Adopted { unwitnessed: bool },
    NotAdopted,
}

pub fn adoption(verification: &Verification, quorum: u64) -> Adoption {
    if (verification.cosigners.len() as u64) < quorum {
        return Adoption::NotAdopted;
    }
    Adoption::Adopted {
        unwitnessed: verification.cosigners.is_empty(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progression {
    Above,
    NotAdopted,
}

pub fn progression(
    offered: &Checkpoint,
    verified_head_epoch_number: u64,
    retained_at_its_height: Option<&Checkpoint>,
) -> Result<Progression, Error> {
    if let Some(retained) = retained_at_its_height {
        if retained.epoch_number() != offered.epoch_number() {
            return Err(Error::Checkpoint(
                "the retained Checkpoint is not the offered Checkpoint's Epoch".into(),
            ));
        }
        if retained.note_text() != offered.note_text() {
            return Err(divergence(
                "two Checkpoints of one Epoch state different note text",
            ));
        }
    }
    if offered.epoch_number() > verified_head_epoch_number {
        return Ok(Progression::Above);
    }
    Ok(Progression::NotAdopted)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Equivocation {
    SameSizeDifferentRoot,
    SameEpochDifferentStatement,
    NoConsistentPrefix,
}

impl Equivocation {
    pub fn code(&self) -> &'static str {
        "WIST3-E02"
    }
}

pub fn equivocation(first: &Checkpoint, second: &Checkpoint) -> Option<Equivocation> {
    if first.note_text() == second.note_text() {
        return None;
    }
    if first.tree_size() == second.tree_size() && first.root() != second.root() {
        return Some(Equivocation::SameSizeDifferentRoot);
    }
    if first.epoch_number() == second.epoch_number() {
        return Some(Equivocation::SameEpochDifferentStatement);
    }
    None
}

pub fn prefix_equivocation(
    smaller: &Checkpoint,
    larger: &Checkpoint,
    larger_tree: &dyn merkle::HashReader,
) -> Result<Option<Equivocation>, Error> {
    if smaller.tree_size() > larger.tree_size() {
        return Err(Error::Checkpoint(
            "the smaller Checkpoint states the larger tree".into(),
        ));
    }
    if merkle::root_from(larger_tree, larger.tree_size())? != *larger.root() {
        return Err(invalid("the tree hashes do not reproduce the larger root"));
    }
    let prefix = merkle::root_from(larger_tree, smaller.tree_size())?;
    Ok((prefix != *smaller.root()).then_some(Equivocation::NoConsistentPrefix))
}

pub fn check_sequence(
    previous: Option<&Checkpoint>,
    next: &Checkpoint,
    cadence_seconds: i64,
) -> Result<(), Error> {
    match previous {
        None => {
            if next.epoch_number() != 0 {
                return Err(Error::Checkpoint(
                    "the first Epoch of the Log is Epoch 0".into(),
                ));
            }
            check_cadence(next, cadence_seconds)
        }
        Some(previous) => check_sequence_at_head(previous, next, cadence_seconds, false, None),
    }
}

pub fn check_sequence_at_head(
    previous: &Checkpoint,
    offered: &Checkpoint,
    cadence_seconds: i64,
    signature_verifies: bool,
    larger_tree: Option<&dyn merkle::HashReader>,
) -> Result<(), Error> {
    if previous.epoch_number().checked_add(1) != Some(offered.epoch_number()) {
        if offered.epoch_number() > previous.epoch_number() {
            return Err(absent_checkpoint(previous.epoch_number() + 1));
        }
        return Err(Error::Checkpoint(
            "the offered Checkpoint is not the Epoch after the verified head".into(),
        ));
    }
    if offered.tree_size() < previous.tree_size() {
        if signature_verifies {
            if let Some(larger_tree) = larger_tree {
                if prefix_equivocation(offered, previous, larger_tree)?.is_some() {
                    return Err(divergence(
                        "a Checkpoint below the previous tree size states a root that is not that tree's at the smaller size",
                    ));
                }
            }
        }
        return Err(invalid(
            "a Checkpoint states a tree size below the Epoch before it",
        ));
    }
    if offered.sealed_at_s()? <= previous.sealed_at_s()? {
        return Err(invalid(
            "sealed_at is not later than the previous Checkpoint's",
        ));
    }
    check_cadence(offered, cadence_seconds)
}

fn check_cadence(checkpoint: &Checkpoint, cadence_seconds: i64) -> Result<(), Error> {
    if cadence_seconds <= 0 {
        return Err(Error::Checkpoint(
            "the sealing cadence in force is not a positive number of seconds".into(),
        ));
    }
    if checkpoint.sealed_at_s()?.rem_euclid(cadence_seconds) != 0 {
        return Err(invalid(
            "sealed_at is off the cadence grid in force at the previous Epoch",
        ));
    }
    Ok(())
}

pub fn check_size_zero_root(checkpoint: &Checkpoint) -> Result<(), Error> {
    if checkpoint.tree_size() != 0 {
        return Ok(());
    }
    merkle::verify_consistency(0, 0, &merkle::EMPTY_ROOT, checkpoint.root(), &[]).map_err(|_| {
        divergence("a Checkpoint states tree size 0 with another root than the empty tree's")
    })
}

pub fn check_consistency(
    previous: &Checkpoint,
    next: &Checkpoint,
    path: &[[u8; 32]],
) -> Result<(), Error> {
    merkle::verify_consistency(
        previous.tree_size(),
        next.tree_size(),
        previous.root(),
        next.root(),
        path,
    )
    .map_err(|e| divergence(&format!("the Consistency Proof fails: {e}")))
}

pub fn archive_path(epoch_number: u64) -> String {
    format!("/log/checkpoints/{epoch_number:09}")
}

pub fn check_archive_path(checkpoint: &Checkpoint, path: &str) -> Result<(), Error> {
    if path != archive_path(checkpoint.epoch_number()) {
        return Err(invalid("the archived Checkpoint is not the path's Epoch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: [u8; 32] = [7u8; 32];

    fn signed(epoch_number: u64, sealed_at: &str, root: [u8; 32]) -> (Checkpoint, AggregatorKey) {
        let key = SigningKey::from_seed(&[3u8; 32]);
        let mut checkpoint =
            Checkpoint::new("log.example.org", 4, root, epoch_number, sealed_at).unwrap();
        checkpoint.sign(&key);
        (
            checkpoint,
            AggregatorKey {
                key_id: "agg-k1".into(),
                public_key: key.public(),
            },
        )
    }

    #[test]
    fn a_signed_note_round_trips_through_parsing() {
        let (checkpoint, key) = signed(0, "2026-08-02T13:00:00Z", ROOT);
        let note = checkpoint.encode();
        let parsed = Checkpoint::parse(&note).unwrap();
        assert_eq!(parsed, checkpoint);
        assert_eq!(parsed.encode(), note);
        verify(&parsed, "log.example.org", &[key], &[]).unwrap();
    }

    #[test]
    fn an_appended_line_leaves_the_note_text_unchanged() {
        let (mut checkpoint, key) = signed(0, "2026-08-02T13:00:00Z", ROOT);
        let text = checkpoint.note_text();
        let witness = SigningKey::from_seed(&[9u8; 32]);
        checkpoint.add_signature(cosignature_line(
            "witness-a.example",
            &witness,
            &text,
            1_775_000_000,
        ));
        assert_eq!(checkpoint.note_text(), text);
        let roster = [WitnessKey {
            name: "witness-a.example".into(),
            public_key: witness.public(),
        }];
        let verification = verify(&checkpoint, "log.example.org", &[key], &roster).unwrap();
        assert_eq!(verification.cosigners.len(), 1);
        assert_eq!(
            adoption(&verification, 1),
            Adoption::Adopted { unwitnessed: false }
        );
        assert_eq!(adoption(&verification, 2), Adoption::NotAdopted);
    }

    #[test]
    fn a_note_carries_sixteen_signature_lines_at_most() {
        let (checkpoint, _) = signed(0, "2026-08-02T13:00:00Z", ROOT);
        let text = checkpoint.note_text();
        let mut lines = Vec::new();
        for index in 0..MAX_SIGNATURE_LINES {
            let key = SigningKey::from_seed(&[index as u8; 32]);
            lines.push(cosignature_line(
                &format!("witness-{index:02}.example"),
                &key,
                &text,
                1_775_000_000,
            ));
        }
        let mut sixteen = checkpoint.clone();
        for line in lines.iter().take(MAX_SIGNATURE_LINES - 1) {
            sixteen.add_signature(line.clone());
        }
        let note = sixteen.encode();
        assert_eq!(Checkpoint::parse(&note).unwrap(), sixteen);

        let mut seventeen = sixteen.clone();
        seventeen.add_signature(lines[MAX_SIGNATURE_LINES - 1].clone());
        let over = seventeen.encode();
        assert!(over.starts_with(&note));
        assert_eq!(
            Checkpoint::parse(&over).unwrap_err().code(),
            Some("WIST3-E03")
        );
    }

    #[test]
    fn a_signature_line_key_name_is_non_empty_and_free_of_plus_and_white_space() {
        let (checkpoint, _) = signed(0, "2026-08-02T13:00:00Z", ROOT);
        let note = checkpoint.encode();
        let line = checkpoint.signatures()[0].encode();
        for name in [
            "",
            "witness+a.example",
            "witness\u{a0}a.example",
            "witness a",
        ] {
            let mut renamed = checkpoint.signatures()[0].clone();
            renamed.name = name.to_string();
            let note = note.replace(&line, &renamed.encode());
            assert_eq!(
                Checkpoint::parse(&note).unwrap_err().code(),
                Some("WIST3-E03"),
                "{name}"
            );
        }
    }

    #[test]
    fn a_root_hash_line_is_exactly_thirty_two_octets_in_canonical_padded_base64() {
        let (checkpoint, _) = signed(0, "2026-08-02T13:00:00Z", ROOT);
        let note = checkpoint.encode();
        let encoded = STANDARD.encode(ROOT);
        for line in [
            STANDARD.encode([7u8; 31]),
            STANDARD.encode([7u8; 33]),
            encoded.trim_end_matches('=').to_string(),
            format!("{}{}", &encoded[..encoded.len() - 2], "5="),
        ] {
            let note = note.replace(&encoded, &line);
            assert_eq!(
                Checkpoint::parse(&note).unwrap_err().code(),
                Some("WIST3-E03"),
                "{line}"
            );
        }
        assert!(!note.ends_with("\n\n"));
        assert_eq!(
            Checkpoint::parse(note.trim_end_matches('\n'))
                .unwrap_err()
                .code(),
            Some("WIST3-E03")
        );
    }

    #[test]
    fn a_checkpoint_without_an_aggregator_signature_is_rejected() {
        let (checkpoint, _) = signed(0, "2026-08-02T13:00:00Z", ROOT);
        let other = SigningKey::from_seed(&[11u8; 32]);
        let err = verify(
            &checkpoint,
            "log.example.org",
            &[AggregatorKey {
                key_id: "other".into(),
                public_key: other.public(),
            }],
            &[],
        )
        .unwrap_err();
        assert_eq!(err.code(), Some("WIST3-E03"));
    }

    #[test]
    fn a_gap_above_the_head_names_the_checkpoint_no_source_serves() {
        let (epoch0, _) = signed(0, "2026-08-02T13:00:00Z", ROOT);
        check_sequence(None, &epoch0, 3600).unwrap();
        let (epoch2, _) = signed(2, "2026-08-02T14:00:00Z", ROOT);
        let err = check_sequence(Some(&epoch0), &epoch2, 3600).unwrap_err();
        assert_eq!(err.code(), Some("WIST3-E01"));
        assert!(err.to_string().contains("Epoch 1"));
        assert_eq!(absent_checkpoint(1).to_string(), err.to_string());
    }

    #[test]
    fn a_sealed_at_that_does_not_advance_or_sits_off_the_grid_is_an_invalid_object() {
        let (epoch0, _) = signed(0, "2026-08-02T13:00:00Z", ROOT);
        let (same_instant, _) = signed(1, "2026-08-02T13:00:00Z", ROOT);
        assert_eq!(
            check_sequence(Some(&epoch0), &same_instant, 3600)
                .unwrap_err()
                .code(),
            Some("WIST3-E03")
        );
        let (earlier, _) = signed(1, "2026-08-02T12:00:00Z", ROOT);
        assert_eq!(
            check_sequence(Some(&epoch0), &earlier, 3600)
                .unwrap_err()
                .code(),
            Some("WIST3-E03")
        );
        let (off_grid, _) = signed(1, "2026-08-02T13:30:00Z", ROOT);
        assert_eq!(
            check_sequence(Some(&epoch0), &off_grid, 3600)
                .unwrap_err()
                .code(),
            Some("WIST3-E03")
        );
        check_sequence(Some(&epoch0), &off_grid, 1800).unwrap();
    }

    #[test]
    fn a_shrinking_tree_is_an_invalid_object_unless_its_root_contradicts_the_prefix() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| merkle::leaf_hash(&[i])).collect();
        let head = Checkpoint::new(
            "log.example.org",
            4,
            merkle::merkle_root(&leaves),
            0,
            "2026-08-02T13:00:00Z",
        )
        .unwrap();
        let tree = merkle::LeafHashes(&leaves);
        let prefix = merkle::merkle_root(&leaves[..3]);

        let restating =
            Checkpoint::new("log.example.org", 3, prefix, 1, "2026-08-02T14:00:00Z").unwrap();
        for signature_verifies in [false, true] {
            assert_eq!(
                check_sequence_at_head(&head, &restating, 3600, signature_verifies, Some(&tree))
                    .unwrap_err()
                    .code(),
                Some("WIST3-E03")
            );
        }

        let contradicting =
            Checkpoint::new("log.example.org", 3, ROOT, 1, "2026-08-02T14:00:00Z").unwrap();
        assert_eq!(
            check_sequence_at_head(&head, &contradicting, 3600, false, Some(&tree))
                .unwrap_err()
                .code(),
            Some("WIST3-E03")
        );
        assert_eq!(
            check_sequence_at_head(&head, &contradicting, 3600, true, None)
                .unwrap_err()
                .code(),
            Some("WIST3-E03")
        );
        assert_eq!(
            check_sequence_at_head(&head, &contradicting, 3600, true, Some(&tree))
                .unwrap_err()
                .code(),
            Some("WIST3-E02")
        );
    }

    #[test]
    fn divergence_prevails_over_an_off_grid_sealed_at_in_the_same_checkpoint() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| merkle::leaf_hash(&[i])).collect();
        let head = Checkpoint::new(
            "log.example.org",
            4,
            merkle::merkle_root(&leaves),
            0,
            "2026-08-02T13:00:00Z",
        )
        .unwrap();
        let off_grid_and_smaller =
            Checkpoint::new("log.example.org", 3, ROOT, 1, "2026-08-02T13:30:00Z").unwrap();
        assert_eq!(
            check_sequence_at_head(
                &head,
                &off_grid_and_smaller,
                3600,
                true,
                Some(&merkle::LeafHashes(&leaves))
            )
            .unwrap_err()
            .code(),
            Some("WIST3-E02")
        );
    }

    #[test]
    fn a_size_zero_checkpoint_stating_a_non_empty_root_fails_consistency() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| merkle::leaf_hash(&[i])).collect();
        let four = Checkpoint::new(
            "log.example.org",
            4,
            merkle::merkle_root(&leaves),
            1,
            "2026-08-02T14:00:00Z",
        )
        .unwrap();
        let empty = Checkpoint::new(
            "log.example.org",
            0,
            merkle::EMPTY_ROOT,
            0,
            "2026-08-02T13:00:00Z",
        )
        .unwrap();
        check_consistency(&empty, &four, &[]).unwrap();
        let stated =
            Checkpoint::new("log.example.org", 0, ROOT, 0, "2026-08-02T13:00:00Z").unwrap();
        assert_eq!(
            check_consistency(&stated, &four, &[]).unwrap_err().code(),
            Some("WIST3-E02")
        );
    }

    #[test]
    fn a_size_zero_checkpoint_is_divergence_unless_it_states_the_empty_root() {
        let empty = Checkpoint::new(
            "log.example.org",
            0,
            merkle::EMPTY_ROOT,
            0,
            "2026-08-02T13:00:00Z",
        )
        .unwrap();
        check_size_zero_root(&empty).unwrap();
        let stated =
            Checkpoint::new("log.example.org", 0, ROOT, 0, "2026-08-02T13:00:00Z").unwrap();
        assert_eq!(
            check_size_zero_root(&stated).unwrap_err().code(),
            Some("WIST3-E02")
        );
        let (populated, _) = signed(0, "2026-08-02T13:00:00Z", ROOT);
        check_size_zero_root(&populated).unwrap();
    }

    #[test]
    fn rollback_is_not_adopted_unless_the_retained_note_text_differs() {
        let (head, _) = signed(2, "2026-08-02T15:00:00Z", ROOT);
        let (lower, _) = signed(1, "2026-08-02T14:00:00Z", ROOT);
        assert_eq!(
            progression(&lower, head.epoch_number(), None).unwrap(),
            Progression::NotAdopted
        );
        assert_eq!(
            progression(&lower, head.epoch_number(), Some(&lower)).unwrap(),
            Progression::NotAdopted
        );
        let (differing, _) = signed(1, "2026-08-02T14:00:00Z", [8u8; 32]);
        let err = progression(&lower, head.epoch_number(), Some(&differing)).unwrap_err();
        assert_eq!(err.code(), Some("WIST3-E02"));
        let (above, _) = signed(3, "2026-08-02T16:00:00Z", ROOT);
        assert_eq!(
            progression(&above, head.epoch_number(), None).unwrap(),
            Progression::Above
        );
    }

    #[test]
    fn the_archive_path_is_the_epoch_number_in_nine_digits() {
        let (checkpoint, _) = signed(2, "2026-08-02T15:00:00Z", ROOT);
        assert_eq!(archive_path(2), "/log/checkpoints/000000002");
        check_archive_path(&checkpoint, "/log/checkpoints/000000002").unwrap();
        let err = check_archive_path(&checkpoint, "/log/checkpoints/000000001").unwrap_err();
        assert_eq!(err.code(), Some("WIST3-E03"));
    }

    #[test]
    fn a_verifier_key_string_carries_the_key_id_and_the_typed_key() {
        let key = SigningKey::from_seed(&[3u8; 32]);
        let encoded = verifier_key("log.example.org", &key.public());
        let mut parts = encoded.split('+');
        assert_eq!(parts.next(), Some("log.example.org"));
        assert_eq!(
            parts.next(),
            Some(hex_encode(&aggregator_key_id("log.example.org", &key.public())).as_str())
        );
        let raw = STANDARD.decode(parts.next().unwrap()).unwrap();
        assert_eq!(raw[0], AGGREGATOR_KEY_TYPE);
        assert_eq!(raw[1..], key.public().to_bytes());
        assert_eq!(parts.next(), None);
    }
}
