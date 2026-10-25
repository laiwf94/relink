//! Random code generation. The rules a code must follow live in
//! `relink_core::code`, re-exported here.

pub use relink_core::code::*;

use crate::util::secure_random;

/// Generates a random base62 code of `len` characters from the OS CSPRNG.
///
/// Uses rejection sampling: bytes >= 248 (the largest multiple of 62 below
/// 256) are discarded so every character is exactly uniform. Codes that
/// collide with a reserved word are regenerated.
pub fn random_code(len: usize) -> String {
    assert!((MIN_CODE_LEN..=MAX_CODE_LEN).contains(&len));
    loop {
        let mut out = String::with_capacity(len);
        let mut buf = [0u8; 64];
        while out.len() < len {
            secure_random(&mut buf);
            for &b in &buf {
                if b < 248 {
                    out.push(ALPHABET[(b % 62) as usize] as char);
                    if out.len() == len {
                        break;
                    }
                }
            }
        }
        if !is_reserved(&out) {
            return out;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest::proptest! {
        #[test]
        fn generated_codes_are_valid(len in MIN_CODE_LEN..=MAX_CODE_LEN) {
            let c = random_code(len);
            proptest::prop_assert_eq!(c.len(), len);
            proptest::prop_assert!(is_plausible_code(&c));
            proptest::prop_assert!(!is_reserved(&c));
        }
    }

    #[test]
    fn random_codes_have_requested_shape() {
        for len in MIN_CODE_LEN..=MAX_CODE_LEN {
            let code = random_code(len);
            assert_eq!(code.len(), len);
            assert!(code.bytes().all(|b| ALPHABET.contains(&b)));
            assert!(is_plausible_code(&code));
        }
    }

    #[test]
    #[should_panic]
    fn random_code_rejects_short_lengths() {
        random_code(3);
    }

    #[test]
    fn random_codes_use_whole_alphabet_evenly() {
        let mut counts = [0usize; 62];
        let samples = 62 * 2000;
        let joined: String = (0..samples / 31).map(|_| random_code(31)).collect();
        for b in joined.bytes() {
            counts[ALPHABET.iter().position(|&a| a == b).unwrap()] += 1;
        }
        let expected = joined.len() as f64 / 62.0;
        for c in counts {
            // Five standard deviations of a binomial count.
            assert!((c as f64 - expected).abs() < 5.0 * expected.sqrt());
        }
    }
}
