//! HyperLogLog++ estimates against exact counts.
//!
//! Every input is generated from fixed seeds, so the numbers are the same on
//! every run. The relative standard error at precision 14 is 0.81%; the
//! bounds below are the 1% the roadmap asks for, measured as the root mean
//! square of the relative error over many independent sketches, plus a
//! bound on the bias and one on the worst single sketch.

use std::collections::HashSet;

use relink_core::hll::{Hll, hash};

/// SplitMix64, a bijection on u64 with uniformly distributed output.
fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// A sketch of `n` distinct items from trial `trial`.
fn sketch(trial: u64, n: u64) -> Hll {
    let mut s = Hll::new();
    for i in 0..n {
        s.insert_hash(mix(i | (trial << 40)));
    }
    s
}

struct Errors {
    rms: f64,
    bias: f64,
    worst: f64,
}

fn errors(results: &[(f64, u64)]) -> Errors {
    let rel: Vec<f64> = results
        .iter()
        .map(|&(est, exact)| (est - exact as f64) / exact as f64)
        .collect();
    let n = rel.len() as f64;
    Errors {
        rms: (rel.iter().map(|e| e * e).sum::<f64>() / n).sqrt(),
        bias: rel.iter().sum::<f64>() / n,
        worst: rel.iter().fold(0.0, |w, e| w.max(e.abs())),
    }
}

#[test]
fn estimates_are_within_one_percent_from_one_to_a_million() {
    // Cardinalities across the sparse form, the switch to dense, the range
    // where most registers are still empty, and far beyond the registers.
    let grid: &[(u64, u64)] = &[
        (10, 64),
        (100, 64),
        (1_000, 64),
        (3_000, 64),
        (3_500, 64),
        (5_000, 64),
        (10_000, 64),
        (20_000, 64),
        (40_000, 48),
        (80_000, 32),
        (160_000, 24),
        (320_000, 16),
        (1_000_000, 8),
    ];
    let mut dense_all = Vec::new();
    for &(n, trials) in grid {
        let results: Vec<(f64, u64)> = (0..trials)
            .map(|t| (sketch(t + n, n).estimate(), n))
            .collect();
        let e = errors(&results);
        eprintln!(
            "n={n:>9} trials={trials:>2} rms={:.4}% bias={:+.4}% worst={:.4}%",
            e.rms * 100.0,
            e.bias * 100.0,
            e.worst * 100.0
        );
        if n <= 3_000 {
            // Sparse: exact but for 25-bit index collisions.
            assert!(e.worst < 0.001, "n={n} worst {}", e.worst);
        } else {
            assert!(e.rms < 0.0125, "n={n} rms {}", e.rms);
            assert!(e.bias.abs() < 0.005, "n={n} bias {}", e.bias);
            assert!(e.worst < 0.035, "n={n} worst {}", e.worst);
            dense_all.extend(results);
        }
    }
    let e = errors(&dense_all);
    eprintln!(
        "dense, all {} sketches: rms={:.4}% bias={:+.4}%",
        dense_all.len(),
        e.rms * 100.0,
        e.bias * 100.0
    );
    assert!(e.rms < 0.01, "pooled rms {}", e.rms);
    assert!(e.bias.abs() < 0.002, "pooled bias {}", e.bias);
}

/// The `k`th visit to `link` on `day`: one of `population` visitors.
fn visitor(scenario: u64, link: u64, day: u64, k: u64, population: u64) -> u64 {
    let pick = mix((scenario << 48) ^ (link << 32) ^ (day << 20) ^ k) % population;
    mix(pick ^ (scenario << 56))
}

/// Visitors of `links` links over `days` days. Each link and day sees
/// `per_cell` visitors drawn from a population, so the same visitor shows
/// up on several links and days; the exact union is counted with a set.
fn links_and_days(scenario: u64, links: u64, days: u64, per_cell: u64, population: u64) {
    let mut cells = Vec::new();
    let mut exact = HashSet::new();
    let mut total = 0u64;
    for link in 0..links {
        for day in 0..days {
            let mut s = Hll::new();
            for k in 0..per_cell {
                let visitor = visitor(scenario, link, day, k, population);
                s.insert_hash(visitor);
                exact.insert(visitor);
                total += 1;
            }
            cells.push(s);
        }
    }
    // Merge in two orders: by link then day, and as one fold in reverse.
    let mut per_link: Vec<Hll> = Vec::new();
    for link in cells.chunks(days as usize) {
        let mut l = Hll::new();
        for cell in link {
            l.merge(cell);
        }
        per_link.push(l);
    }
    let mut by_link = Hll::new();
    for l in &per_link {
        by_link.merge(l);
    }
    let mut folded = Hll::new();
    for cell in cells.iter().rev() {
        folded.merge(cell);
    }
    assert_eq!(by_link, folded, "merge order changed the sketch");
    let direct = {
        let mut s = Hll::new();
        for &v in &exact {
            s.insert_hash(v);
        }
        s
    };
    assert_eq!(
        by_link, direct,
        "merged sketch differs from the sketch of the union"
    );

    let n = exact.len() as u64;
    let err = (by_link.estimate() - n as f64) / n as f64;
    eprintln!(
        "{links} links x {days} days, {total} visits, {n} distinct: estimate {} ({:+.3}%)",
        by_link.count(),
        err * 100.0
    );
    assert!(err.abs() < 0.03, "error {err}");
    // A link's own sketch over all days is right too.
    let first = &per_link[0];
    let exact_first: HashSet<u64> = (0..days)
        .flat_map(|day| (0..per_cell).map(move |k| visitor(scenario, 0, day, k, population)))
        .collect();
    let m = exact_first.len() as f64;
    assert!(((first.estimate() - m) / m).abs() < 0.03);
}

#[test]
fn sketches_merged_across_links_and_days_are_the_sketch_of_the_union() {
    // Small links that stay sparse in every cell and merge into a dense
    // total, and busy links that are dense on their own.
    let scenarios: &[(u64, u64, u64, u64)] = &[
        (40, 30, 100, 50_000),
        (40, 30, 100, 1_000_000),
        (10, 30, 2_000, 100_000),
        (5, 7, 20_000, 300_000),
        (100, 1, 500, 40_000),
    ];
    for (i, &(links, days, per_cell, population)) in scenarios.iter().enumerate() {
        links_and_days(i as u64, links, days, per_cell, population);
    }
}

#[test]
fn the_pooled_error_of_merged_sketches_is_under_one_percent() {
    // Many independent merges of 30 daily sketches each: the error of a
    // merged sketch is that of one built directly, under 1% RMS.
    let mut results = Vec::new();
    for trial in 0..48u64 {
        let mut total = Hll::new();
        for day in 0..30u64 {
            let mut s = Hll::new();
            // Days overlap by half: day d sees visitors 1000d .. 1000d+2000.
            for v in day * 1_000..day * 1_000 + 2_000 {
                s.insert_hash(mix(v ^ trial << 40));
            }
            total.merge(&s);
        }
        results.push((total.estimate(), 31_000));
    }
    let e = errors(&results);
    eprintln!(
        "48 merges of 30 days, 31,000 distinct: rms={:.4}% bias={:+.4}% worst={:.4}%",
        e.rms * 100.0,
        e.bias * 100.0,
        e.worst * 100.0
    );
    assert!(e.rms < 0.01, "rms {}", e.rms);
    assert!(e.worst < 0.03, "worst {}", e.worst);
}

#[test]
fn hashing_byte_items_is_as_accurate_as_uniform_hashes() {
    // The SHA-256 path, fed visitor-like 16-byte values and short strings.
    let mut results = Vec::new();
    for trial in 0..16u64 {
        let mut s = Hll::new();
        for i in 0..50_000u64 {
            let mut item = [0u8; 16];
            item[..8].copy_from_slice(&trial.to_le_bytes());
            item[8..].copy_from_slice(&i.to_le_bytes());
            s.insert(&item);
        }
        results.push((s.estimate(), 50_000));
    }
    let e = errors(&results);
    assert!(
        e.rms < 0.0125 && e.worst < 0.035,
        "rms {} worst {}",
        e.rms,
        e.worst
    );

    let mut s = Hll::new();
    for i in 0..2_000 {
        s.insert(format!("visitor-{i}").as_bytes());
    }
    assert!(s.is_sparse());
    assert!(s.count().abs_diff(2_000) <= 2, "{}", s.count());
    assert_eq!(hash(b"visitor-1"), hash(b"visitor-1"));
}

#[test]
fn stored_sketches_merge_like_live_ones() {
    // Sketches go to the database as bytes and come back to be merged.
    let a = sketch(1, 2_500);
    let b = sketch(2, 40_000);
    let mut live = a.clone();
    live.merge(&b);
    let mut stored = Hll::from_bytes(&a.to_bytes()).unwrap();
    stored.merge(&Hll::from_bytes(&b.to_bytes()).unwrap());
    assert_eq!(stored, live);
    assert_eq!(stored.to_bytes(), live.to_bytes());
    assert!(a.to_bytes().len() < 9_000, "{}", a.to_bytes().len());
    assert_eq!(b.to_bytes().len(), 3 + 12_288);
}
