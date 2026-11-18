//! HyperLogLog++ sketches for unique counts.
//!
//! A sketch estimates how many distinct items were added to it in a fixed
//! amount of space, and two sketches merge into the sketch of the union of
//! their items. So a unique visitor count over many links and many days is
//! the merge of one sketch per link and day, never a scan of visitor rows.
//!
//! This follows Heule, Nunkesser and Hall, "HyperLogLog in Practice:
//! Algorithmic Engineering of a State of The Art Cardinality Estimation
//! Algorithm" (EDBT 2013): a 64-bit hash, precision 14 (16,384 registers),
//! and a sparse form at precision 25 for small sets that is exact in
//! practice and converts to the dense form once it would be larger. The
//! paper corrects the dense estimate with empirical bias tables; instead the
//! dense estimate here is Ertl's improved estimator ("New cardinality
//! estimation algorithms for HyperLogLog sketches", 2017, algorithm 6),
//! which needs no tables and is unbiased across the whole range. Its
//! relative standard error is 1.04/√16384 = 0.81%.
//!
//! Every sketch has the same precision, so any two merge. A sketch's
//! representation depends only on the set of hashes added, not on the order
//! or on how it was assembled from merges, so equal sets give equal bytes.
//!
//! The sparse form keeps 25 bits of each item's hash. Items must therefore
//! be values an attacker cannot enumerate and hash, such as the keyed
//! visitor hashes, never raw addresses.

use std::fmt;

use sha2::{Digest, Sha256};

/// Dense precision: the first 14 bits of a hash pick one of 2^14 registers.
pub const PRECISION: u32 = 14;
/// Sparse precision: the first 25 bits of a hash are kept exactly.
pub const SPARSE_PRECISION: u32 = 25;

const M: usize = 1 << PRECISION;
/// Bits of the hash after the register index, `q` in Ertl's paper.
const Q: u32 = 64 - PRECISION;
/// Largest register value: `Q` zero bits and the one after them.
const MAX_RHO: u8 = (Q + 1) as u8;
/// Index bits the sparse form keeps beyond the dense index.
const EXTRA: u32 = SPARSE_PRECISION - PRECISION;
const EXTRA_MASK: u32 = (1 << EXTRA) - 1;
/// Hash bits after the sparse index.
const SPARSE_Q: u32 = 64 - SPARSE_PRECISION;
const RHO_BITS: u32 = 6;
const RHO_MASK: u32 = (1 << RHO_BITS) - 1;

/// Bytes of the dense registers packed at 6 bits each.
pub const DENSE_BYTES: usize = M * 6 / 8;
/// Most entries a sparse sketch holds. At 4 bytes each in memory, one more
/// would take more room than the dense registers.
pub const SPARSE_LIMIT: usize = DENSE_BYTES / 4;

const FORMAT_VERSION: u8 = 1;
const KIND_SPARSE: u8 = 0;
const KIND_DENSE: u8 = 1;
const HEADER: usize = 3;

/// α∞ = 1 / (2 ln 2).
const ALPHA_INF: f64 = 0.721_347_520_444_481_7;

/// A HyperLogLog++ sketch at precision 14.
#[derive(Clone, PartialEq, Eq)]
pub struct Hll {
    repr: Repr,
}

#[derive(Clone, PartialEq, Eq)]
enum Repr {
    /// Entries sorted by sparse index, one per index; see [`sparse_entry`].
    Sparse(Vec<u32>),
    /// One register value (0 to 51) per byte.
    Dense(Box<[u8]>),
}

impl Default for Hll {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Hll {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let form = if self.is_sparse() { "sparse" } else { "dense" };
        write!(f, "Hll({form}, ~{})", self.count())
    }
}

/// Why bytes are not a sketch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Shorter than its header or its declared content.
    Truncated,
    /// A format version this build does not read.
    Version(u8),
    /// A precision other than [`PRECISION`].
    Precision(u8),
    /// Neither sparse nor dense.
    Kind(u8),
    /// Bytes after the end of the sketch.
    TrailingBytes,
    /// More sparse entries than [`SPARSE_LIMIT`].
    TooManyEntries,
    /// Sparse indexes not strictly increasing, or past 2^25.
    BadIndex,
    /// A varint longer than a 25-bit value needs.
    BadVarint,
    /// A register or sparse value that no hash can produce.
    BadValue,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "sketch is truncated"),
            DecodeError::Version(v) => write!(f, "unknown sketch format version {v}"),
            DecodeError::Precision(p) => write!(f, "sketch precision {p}, expected {PRECISION}"),
            DecodeError::Kind(k) => write!(f, "unknown sketch kind {k}"),
            DecodeError::TrailingBytes => write!(f, "bytes after the end of the sketch"),
            DecodeError::TooManyEntries => write!(f, "too many sparse entries"),
            DecodeError::BadIndex => write!(f, "sparse indexes out of order or range"),
            DecodeError::BadVarint => write!(f, "malformed varint"),
            DecodeError::BadValue => write!(f, "register value out of range"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// The 64-bit hash of an item: the first 8 bytes of its SHA-256. Stable
/// across builds and platforms, because stored sketches depend on it.
pub fn hash(item: &[u8]) -> u64 {
    let digest = Sha256::digest(item);
    u64::from_be_bytes(digest[..8].try_into().expect("8 bytes"))
}

/// The sparse entry for a hash: the first 25 bits as the index, shifted
/// left 6. When the 11 index bits after the dense index are all zero, the
/// dense register value cannot be read from the index, so the low 6 bits
/// hold the run length of the remaining 39 bits (1 to 40); otherwise they
/// are zero.
fn sparse_entry(h: u64) -> u32 {
    let idx = (h >> SPARSE_Q) as u32;
    if idx & EXTRA_MASK != 0 {
        idx << RHO_BITS
    } else {
        let rest = h << SPARSE_PRECISION;
        let rho = rest.leading_zeros().min(SPARSE_Q) + 1;
        (idx << RHO_BITS) | rho
    }
}

fn entry_index(e: u32) -> u32 {
    e >> RHO_BITS
}

/// The dense register and value a sparse entry stands for: the same as
/// adding the hash it came from to a dense sketch.
fn entry_to_dense(e: u32) -> (usize, u8) {
    let idx = entry_index(e);
    let reg = (idx >> EXTRA) as usize;
    let low = idx & EXTRA_MASK;
    let rho = if low != 0 {
        low.leading_zeros() - (32 - EXTRA) + 1
    } else {
        (e & RHO_MASK) + EXTRA
    };
    (reg, rho as u8)
}

fn dense_of(h: u64) -> (usize, u8) {
    let reg = (h >> Q) as usize;
    let rho = (h << PRECISION).leading_zeros().min(Q) + 1;
    (reg, rho as u8)
}

/// Adds `e` to sorted, deduplicated `entries`, keeping the larger value for
/// an index already there.
fn sparse_add(entries: &mut Vec<u32>, e: u32) {
    match entries.binary_search_by_key(&entry_index(e), |&x| entry_index(x)) {
        Ok(i) => entries[i] = entries[i].max(e),
        Err(i) => entries.insert(i, e),
    }
}

impl Hll {
    /// An empty sketch, in the sparse form.
    pub fn new() -> Self {
        Hll {
            repr: Repr::Sparse(Vec::new()),
        }
    }

    /// Adds an item, hashed with [`hash`].
    pub fn insert(&mut self, item: &[u8]) {
        self.insert_hash(hash(item));
    }

    /// Adds an item by a 64-bit hash of it. The hash must be uniformly
    /// distributed, such as the first 8 bytes of a keyed visitor hash.
    pub fn insert_hash(&mut self, h: u64) {
        match &mut self.repr {
            Repr::Sparse(entries) => {
                sparse_add(entries, sparse_entry(h));
                if entries.len() > SPARSE_LIMIT {
                    self.densify();
                }
            }
            Repr::Dense(regs) => {
                let (reg, rho) = dense_of(h);
                if regs[reg] < rho {
                    regs[reg] = rho;
                }
            }
        }
    }

    /// Makes this the sketch of the union of both sketches' items.
    pub fn merge(&mut self, other: &Hll) {
        match (&mut self.repr, &other.repr) {
            (Repr::Sparse(mine), Repr::Sparse(theirs)) => {
                let merged = merge_sorted(mine, theirs);
                let over = merged.len() > SPARSE_LIMIT;
                *mine = merged;
                if over {
                    self.densify();
                }
            }
            (Repr::Sparse(mine), Repr::Dense(theirs)) => {
                let mut regs = theirs.clone();
                apply_sparse(&mut regs, mine);
                self.repr = Repr::Dense(regs);
            }
            (Repr::Dense(regs), Repr::Sparse(theirs)) => apply_sparse(regs, theirs),
            (Repr::Dense(regs), Repr::Dense(theirs)) => {
                for (a, &b) in regs.iter_mut().zip(theirs.iter()) {
                    *a = (*a).max(b);
                }
            }
        }
    }

    fn densify(&mut self) {
        if let Repr::Sparse(entries) = &self.repr {
            let mut regs = vec![0u8; M].into_boxed_slice();
            apply_sparse(&mut regs, entries);
            self.repr = Repr::Dense(regs);
        }
    }

    /// Whether the sketch is still in the sparse form.
    pub fn is_sparse(&self) -> bool {
        matches!(self.repr, Repr::Sparse(_))
    }

    /// Whether nothing was ever added.
    pub fn is_empty(&self) -> bool {
        match &self.repr {
            Repr::Sparse(entries) => entries.is_empty(),
            Repr::Dense(regs) => regs.iter().all(|&r| r == 0),
        }
    }

    /// The estimated number of distinct items.
    pub fn estimate(&self) -> f64 {
        match &self.repr {
            Repr::Sparse(entries) => {
                // Linear counting over 2^25 buckets: at most 3,072 of them
                // are taken, so it is all but exact.
                let m = (1u64 << SPARSE_PRECISION) as f64;
                let empty = m - entries.len() as f64;
                m * (m / empty).ln()
            }
            Repr::Dense(regs) => {
                let mut hist = [0u32; MAX_RHO as usize + 1];
                for &r in regs.iter() {
                    hist[r as usize] += 1;
                }
                ertl_estimate(&hist)
            }
        }
    }

    /// [`Hll::estimate`] rounded to a whole number.
    pub fn count(&self) -> u64 {
        self.estimate().round() as u64
    }

    /// The dense register values, whichever form the sketch is in.
    pub fn registers(&self) -> Vec<u8> {
        match &self.repr {
            Repr::Sparse(entries) => {
                let mut regs = vec![0u8; M];
                apply_sparse(&mut regs, entries);
                regs
            }
            Repr::Dense(regs) => regs.to_vec(),
        }
    }

    /// Bytes this sketch takes in memory, not counting the struct itself.
    pub fn heap_bytes(&self) -> usize {
        match &self.repr {
            Repr::Sparse(entries) => entries.capacity() * 4,
            Repr::Dense(regs) => regs.len(),
        }
    }

    /// The stored form: version, precision and kind, then for a sparse
    /// sketch the entry count and, per entry, the varint gap from the
    /// previous index followed by its run-length byte where it has one;
    /// for a dense sketch the 16,384 registers packed at 6 bits, low bits
    /// first. Equal sketches give equal bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.repr {
            Repr::Sparse(entries) => {
                let mut out = Vec::with_capacity(HEADER + 5 + entries.len() * 3);
                out.extend_from_slice(&[FORMAT_VERSION, PRECISION as u8, KIND_SPARSE]);
                put_varint(&mut out, entries.len() as u32);
                let mut prev = 0;
                for &e in entries {
                    let idx = entry_index(e);
                    put_varint(&mut out, idx - prev);
                    prev = idx;
                    if idx & EXTRA_MASK == 0 {
                        out.push((e & RHO_MASK) as u8);
                    }
                }
                out
            }
            Repr::Dense(regs) => {
                let mut out = vec![0u8; HEADER + DENSE_BYTES];
                out[..HEADER].copy_from_slice(&[FORMAT_VERSION, PRECISION as u8, KIND_DENSE]);
                let packed = &mut out[HEADER..];
                for (i, chunk) in regs.as_chunks::<4>().0.iter().enumerate() {
                    let v = chunk[0] as u32
                        | (chunk[1] as u32) << 6
                        | (chunk[2] as u32) << 12
                        | (chunk[3] as u32) << 18;
                    packed[i * 3..i * 3 + 3].copy_from_slice(&v.to_le_bytes()[..3]);
                }
                out
            }
        }
    }

    /// Reads [`Hll::to_bytes`] output, refusing anything it could not have
    /// written.
    pub fn from_bytes(bytes: &[u8]) -> Result<Hll, DecodeError> {
        let [version, precision, kind, body @ ..] = bytes else {
            return Err(DecodeError::Truncated);
        };
        if *version != FORMAT_VERSION {
            return Err(DecodeError::Version(*version));
        }
        if u32::from(*precision) != PRECISION {
            return Err(DecodeError::Precision(*precision));
        }
        match *kind {
            KIND_SPARSE => {
                let mut pos = 0;
                let n = get_varint(body, &mut pos)? as usize;
                if n > SPARSE_LIMIT {
                    return Err(DecodeError::TooManyEntries);
                }
                let mut entries = Vec::with_capacity(n);
                let mut prev: u32 = 0;
                for i in 0..n {
                    let gap = get_varint(body, &mut pos)?;
                    if i > 0 && gap == 0 {
                        return Err(DecodeError::BadIndex);
                    }
                    // Both are below 2^28, so this cannot overflow.
                    let idx = prev + gap;
                    if idx >= 1 << SPARSE_PRECISION {
                        return Err(DecodeError::BadIndex);
                    }
                    prev = idx;
                    let rho = if idx & EXTRA_MASK == 0 {
                        let r = *body.get(pos).ok_or(DecodeError::Truncated)?;
                        pos += 1;
                        if r == 0 || u32::from(r) > SPARSE_Q + 1 {
                            return Err(DecodeError::BadValue);
                        }
                        u32::from(r)
                    } else {
                        0
                    };
                    entries.push((idx << RHO_BITS) | rho);
                }
                if pos != body.len() {
                    return Err(DecodeError::TrailingBytes);
                }
                Ok(Hll {
                    repr: Repr::Sparse(entries),
                })
            }
            KIND_DENSE => {
                if body.len() < DENSE_BYTES {
                    return Err(DecodeError::Truncated);
                }
                if body.len() > DENSE_BYTES {
                    return Err(DecodeError::TrailingBytes);
                }
                let mut regs = vec![0u8; M].into_boxed_slice();
                for (i, chunk) in body.as_chunks::<3>().0.iter().enumerate() {
                    let v = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], 0]);
                    for j in 0..4 {
                        let r = ((v >> (6 * j)) & 63) as u8;
                        if r > MAX_RHO {
                            return Err(DecodeError::BadValue);
                        }
                        regs[i * 4 + j] = r;
                    }
                }
                Ok(Hll {
                    repr: Repr::Dense(regs),
                })
            }
            other => Err(DecodeError::Kind(other)),
        }
    }
}

fn apply_sparse(regs: &mut [u8], entries: &[u32]) {
    for &e in entries {
        let (reg, rho) = entry_to_dense(e);
        if regs[reg] < rho {
            regs[reg] = rho;
        }
    }
}

/// The union of two sorted entry lists, keeping the larger value per index.
fn merge_sorted(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        let (ia, ib) = (entry_index(a[i]), entry_index(b[j]));
        if ia < ib {
            out.push(a[i]);
            i += 1;
        } else if ib < ia {
            out.push(b[j]);
            j += 1;
        } else {
            out.push(a[i].max(b[j]));
            i += 1;
            j += 1;
        }
    }
    out.extend_from_slice(&a[i..]);
    out.extend_from_slice(&b[j..]);
    out
}

/// Ertl's improved raw estimator from the histogram of register values.
fn ertl_estimate(hist: &[u32; MAX_RHO as usize + 1]) -> f64 {
    let m = M as f64;
    if hist[0] as usize == M {
        return 0.0;
    }
    let mut z = m * tau(1.0 - f64::from(hist[Q as usize + 1]) / m);
    for k in (1..=Q as usize).rev() {
        z = 0.5 * (z + f64::from(hist[k]));
    }
    z += m * sigma(f64::from(hist[0]) / m);
    ALPHA_INF * m * m / z
}

/// σ(x) = x + Σ_{k≥1} x^(2^k) 2^(k-1), for 0 ≤ x < 1.
fn sigma(mut x: f64) -> f64 {
    let mut y = 1.0;
    let mut z = x;
    loop {
        x *= x;
        let prev = z;
        z += x * y;
        y += y;
        if z == prev {
            return z;
        }
    }
}

/// τ(x) = (1 - x - Σ_{k≥1} (1 - x^(2^-k))² 2^-k) / 3, for 0 ≤ x ≤ 1.
fn tau(mut x: f64) -> f64 {
    if x == 0.0 || x == 1.0 {
        return 0.0;
    }
    let mut y = 1.0;
    let mut z = 1.0 - x;
    loop {
        x = x.sqrt();
        let prev = z;
        y *= 0.5;
        z -= (1.0 - x) * (1.0 - x) * y;
        if z == prev {
            return z / 3.0;
        }
    }
}

fn put_varint(out: &mut Vec<u8>, mut v: u32) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// A LEB128 varint of at most 4 bytes (28 bits), in its shortest form.
fn get_varint(buf: &[u8], pos: &mut usize) -> Result<u32, DecodeError> {
    let mut v: u32 = 0;
    for i in 0..4 {
        let b = *buf.get(*pos).ok_or(DecodeError::Truncated)?;
        *pos += 1;
        v |= u32::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            if b == 0 && i > 0 {
                return Err(DecodeError::BadVarint);
            }
            return Ok(v);
        }
    }
    Err(DecodeError::BadVarint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// SplitMix64: distinct, uniformly distributed test hashes.
    fn mix(mut z: u64) -> u64 {
        z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn sketch(hashes: impl IntoIterator<Item = u64>) -> Hll {
        let mut s = Hll::new();
        for h in hashes {
            s.insert_hash(h);
        }
        s
    }

    fn dense_direct(hashes: impl IntoIterator<Item = u64>) -> Vec<u8> {
        let mut regs = vec![0u8; M];
        for h in hashes {
            let (reg, rho) = dense_of(h);
            regs[reg] = regs[reg].max(rho);
        }
        regs
    }

    #[test]
    fn sizes_follow_from_the_precision() {
        assert_eq!(M, 16_384);
        assert_eq!(DENSE_BYTES, 12_288);
        assert_eq!(SPARSE_LIMIT, 3_072);
        assert_eq!(MAX_RHO, 51);
        assert!((ALPHA_INF - 1.0 / (2.0 * 2f64.ln())).abs() < 1e-15);
    }

    #[test]
    fn empty_one_and_duplicates() {
        let mut s = Hll::new();
        assert!(s.is_empty() && s.is_sparse());
        assert_eq!(s.count(), 0);
        s.insert(b"visitor-a");
        assert!(!s.is_empty());
        assert_eq!(s.count(), 1);
        for _ in 0..100 {
            s.insert(b"visitor-a");
        }
        assert_eq!(s.count(), 1);
        s.insert(b"visitor-b");
        assert_eq!(s.count(), 2);
        assert_eq!(format!("{s:?}"), "Hll(sparse, ~2)");
    }

    #[test]
    fn hash_is_stable() {
        // SHA-256("") starts e3b0c442 98fc1c14.
        assert_eq!(hash(b""), 0xe3b0_c442_98fc_1c14);
    }

    #[test]
    fn extreme_hashes_reach_the_largest_values() {
        // A hash whose bits after the dense index are all zero gives the
        // largest register value in both forms.
        for h in [0u64, 1, 5u64 << Q, u64::MAX, 1u64 << 39, 1u64 << 38] {
            let s = sketch([h]);
            assert_eq!(s.registers(), dense_direct([h]), "{h:#x}");
        }
        assert_eq!(dense_of(0), (0, 51));
        assert_eq!(entry_to_dense(sparse_entry(0)), (0, 51));
        assert_eq!(dense_of(u64::MAX), (M - 1, 1));
        assert_eq!(entry_to_dense(sparse_entry(u64::MAX)), (M - 1, 1));
    }

    #[test]
    fn becomes_dense_past_the_limit_with_the_same_registers() {
        let hashes: Vec<u64> = (0..20_000).map(mix).collect();
        let mut s = Hll::new();
        let mut became_dense_at = None;
        for (i, &h) in hashes.iter().enumerate() {
            s.insert_hash(h);
            if became_dense_at.is_none() && !s.is_sparse() {
                became_dense_at = Some(i + 1);
                assert_eq!(s.registers(), dense_direct(hashes[..=i].iter().copied()));
            }
        }
        // 20,000 hashes keep almost exactly 20,000 distinct 25-bit indexes,
        // so the switch comes at entry 3,073.
        assert_eq!(became_dense_at, Some(SPARSE_LIMIT + 1));
        assert_eq!(s.registers(), dense_direct(hashes.iter().copied()));
        assert_eq!(s.heap_bytes(), M);
        assert_eq!(s.to_bytes().len(), HEADER + DENSE_BYTES);
    }

    #[test]
    fn sparse_counts_are_exact_in_practice() {
        // Only two items whose first 25 hash bits are equal count once:
        // about n²/2^26 pairs, 0.14 at the limit.
        for n in [1u64, 2, 3, 10, 100, 1_000, 2_000, SPARSE_LIMIT as u64] {
            for seed in 0..8u64 {
                let s = sketch((0..n).map(|i| mix(i + (seed << 32))));
                assert!(s.is_sparse());
                assert!(
                    s.count().abs_diff(n) <= 1 + n / 1_000,
                    "n={n} got {}",
                    s.count()
                );
            }
        }
    }

    #[test]
    fn sparse_bytes_are_small() {
        let s = sketch((0..1_000).map(mix));
        let len = s.to_bytes().len();
        // Gaps of ~2^25/1000 take 2 or 3 bytes; one entry in 2,048 carries
        // a run-length byte.
        assert!(len < 3_000, "{len}");
        assert_eq!(Hll::from_bytes(&s.to_bytes()).unwrap(), s);
        assert_eq!(Hll::new().to_bytes(), vec![1, 14, 0, 0]);
    }

    #[test]
    fn merges_across_forms() {
        let a: Vec<u64> = (0..500).map(mix).collect();
        let b: Vec<u64> = (300..10_000).map(mix).collect();
        let c: Vec<u64> = (9_000..30_000).map(mix).collect();
        let all = || a.iter().chain(&b).chain(&c).copied();
        let (sa, sb, sc) = (sketch(a.clone()), sketch(b.clone()), sketch(c.clone()));
        assert!(sa.is_sparse() && !sb.is_sparse() && !sc.is_sparse());

        // sparse into dense, dense into sparse, dense into dense
        let mut x = sb.clone();
        x.merge(&sa);
        x.merge(&sc);
        let mut y = sa.clone();
        y.merge(&sc);
        y.merge(&sb);
        let direct = sketch(all());
        assert_eq!(x, direct);
        assert_eq!(y, direct);

        // Two sparse sketches whose union is past the limit.
        let p = sketch((0..2_000).map(mix));
        let q = sketch((2_000..4_000).map(mix));
        assert!(p.is_sparse() && q.is_sparse());
        let mut pq = p.clone();
        pq.merge(&q);
        assert!(!pq.is_sparse());
        assert_eq!(pq, sketch((0..4_000).map(mix)));
    }

    #[test]
    fn dense_round_trips_and_packs_every_value() {
        let mut s = sketch((0..50_000).map(mix));
        if let Repr::Dense(regs) = &mut s.repr {
            for (i, r) in regs.iter_mut().enumerate().take(52) {
                *r = i as u8;
            }
        }
        let bytes = s.to_bytes();
        assert_eq!(Hll::from_bytes(&bytes).unwrap(), s);
        assert_eq!(Hll::from_bytes(&bytes).unwrap().to_bytes(), bytes);
    }

    #[test]
    fn refuses_what_it_could_not_have_written() {
        use DecodeError::*;
        let dense = sketch((0..10_000).map(mix)).to_bytes();
        let sparse = sketch((0..100).map(mix)).to_bytes();
        let cases: Vec<(Vec<u8>, DecodeError)> = vec![
            (vec![], Truncated),
            (vec![1, 14], Truncated),
            (vec![2, 14, 0, 0], Version(2)),
            (vec![1, 12, 0, 0], Precision(12)),
            (vec![1, 14, 7], Kind(7)),
            (vec![1, 14, 0], Truncated),
            (vec![1, 14, 0, 0, 0], TrailingBytes),
            (dense[..dense.len() - 1].to_vec(), Truncated),
            ([&dense[..], &[0]].concat(), TrailingBytes),
            (sparse[..sparse.len() - 1].to_vec(), Truncated),
            ([&sparse[..], &[0]].concat(), TrailingBytes),
            // 3,073 entries
            (vec![1, 14, 0, 0x81, 0x18], TooManyEntries),
            // two entries at index 1 and again at 1
            (vec![1, 14, 0, 2, 1, 0], BadIndex),
            // index 2^25
            (vec![1, 14, 0, 1, 0x80, 0x80, 0x80, 0x10], BadIndex),
            // index 2^25 reached by gaps
            (
                vec![1, 14, 0, 2, 0xff, 0xff, 0xff, 0x0f, 0xff, 0xff, 0xff, 0x0f],
                BadIndex,
            ),
            // a five-byte varint, and a padded one
            (vec![1, 14, 0, 0x80, 0x80, 0x80, 0x80, 0x01], BadVarint),
            (vec![1, 14, 0, 0x81, 0x00, 1], BadVarint),
            // index 0 needs a run length of 1 to 40
            (vec![1, 14, 0, 1, 0, 0], BadValue),
            (vec![1, 14, 0, 1, 0, 41], BadValue),
            (vec![1, 14, 0, 1, 0], Truncated),
        ];
        for (bytes, want) in cases {
            assert_eq!(Hll::from_bytes(&bytes), Err(want), "{bytes:?}");
            assert!(!want.to_string().is_empty());
        }
        let mut bad = dense.clone();
        bad[HEADER] = 52; // register 0 = 52
        assert_eq!(Hll::from_bytes(&bad), Err(BadValue));
        assert_eq!(
            Hll::from_bytes(&[1, 14, 0, 1, 0, 40]).unwrap().registers()[0],
            51
        );
    }

    #[test]
    fn estimator_series_match_their_closed_forms() {
        // σ(x) and τ(x) at points where the sums are easy to check.
        assert_eq!(sigma(0.0), 0.0);
        let x: f64 = 0.5;
        let series: f64 = x
            + (1..20)
                .map(|k| x.powi(1 << k) * 2f64.powi(k - 1))
                .sum::<f64>();
        assert!((sigma(x) - series).abs() < 1e-12);
        assert_eq!(tau(0.0), 0.0);
        assert_eq!(tau(1.0), 0.0);
        let t: f64 = (1.0
            - x
            - (1..60)
                .map(|k| (1.0 - x.powf(2f64.powi(-k))).powi(2) * 2f64.powi(-k))
                .sum::<f64>())
            / 3.0;
        assert!((tau(x) - t).abs() < 1e-12);
        // Every register at its largest value, which takes about 2^64
        // items: there is nothing left to estimate from, and the count
        // saturates instead of wrapping.
        let mut hist = [0u32; MAX_RHO as usize + 1];
        hist[MAX_RHO as usize] = M as u32;
        assert_eq!(ertl_estimate(&hist), f64::INFINITY);
        let full = Hll::from_bytes(&[&[1, 14, 1][..], &[0xff; DENSE_BYTES][..]].concat());
        assert_eq!(full, Err(DecodeError::BadValue));
        let mut full = sketch([0]);
        full.densify();
        if let Repr::Dense(regs) = &mut full.repr {
            regs.fill(MAX_RHO);
        }
        assert_eq!(full.count(), u64::MAX);
    }

    #[test]
    fn varints_round_trip() {
        for v in [
            0u32,
            1,
            127,
            128,
            16_383,
            16_384,
            (1 << 25) - 1,
            (1 << 28) - 1,
        ] {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            let mut pos = 0;
            assert_eq!(get_varint(&out, &mut pos), Ok(v));
            assert_eq!(pos, out.len());
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn merge_is_the_sketch_of_the_union(
            a in prop::collection::vec(any::<u64>(), 0..4_000),
            b in prop::collection::vec(any::<u64>(), 0..4_000),
            c in prop::collection::vec(any::<u64>(), 0..300),
        ) {
            let (sa, sb, sc) = (sketch(a.clone()), sketch(b.clone()), sketch(c.clone()));
            let union = sketch(a.iter().chain(&b).chain(&c).copied());
            let mut ab = sa.clone();
            ab.merge(&sb);
            let mut ba = sb.clone();
            ba.merge(&sa);
            prop_assert_eq!(&ab, &ba);
            let mut ab_c = ab.clone();
            ab_c.merge(&sc);
            let mut bc = sb.clone();
            bc.merge(&sc);
            let mut a_bc = sa.clone();
            a_bc.merge(&bc);
            prop_assert_eq!(&ab_c, &a_bc);
            prop_assert_eq!(&ab_c, &union);
            let mut again = ab_c.clone();
            again.merge(&sc);
            again.merge(&union);
            prop_assert_eq!(&again, &union);
            prop_assert_eq!(union.registers(), dense_direct(a.iter().chain(&b).chain(&c).copied()));
            let bytes = union.to_bytes();
            prop_assert_eq!(Hll::from_bytes(&bytes).unwrap(), union);
        }

        #[test]
        fn random_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            let mut with_header = vec![1, 14, 0];
            with_header.extend_from_slice(&bytes);
            for input in [&bytes[..], &with_header[..]] {
                if let Ok(s) = Hll::from_bytes(input) {
                    prop_assert_eq!(s.to_bytes(), input.to_vec());
                }
            }
        }
    }
}
