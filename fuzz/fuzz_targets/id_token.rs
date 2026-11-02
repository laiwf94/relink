//! OpenID Connect parsers: ID tokens, JWK sets, base64url and return paths.
//! None may panic; a random token must never verify, and base64url must
//! round-trip whatever it accepts.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use relink_server::oidc::{Expected, Jwks, safe_return_to, verify_id_token};
use relink_server::util::{b64url_decode, b64url_encode};

/// An RSA key (RFC 7515 appendix A.2) and a P-256 key (appendix A.3).
fn keys() -> &'static Jwks {
    static KEYS: OnceLock<Jwks> = OnceLock::new();
    KEYS.get_or_init(|| {
        Jwks::parse(
            br#"{"keys":[
              {"kty":"RSA","kid":"rsa","e":"AQAB","n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"},
              {"kty":"EC","kid":"ec","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}
            ]}"#,
        )
        .expect("the fixed key set parses")
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = Jwks::parse(data);
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let expected = Expected {
        issuer: "https://id.example.com",
        client_id: "relink",
        nonce: "n",
        now: 1_800_000_000,
    };
    assert!(verify_id_token(s, keys(), &expected).is_err());
    if let Some(bytes) = b64url_decode(s) {
        assert_eq!(b64url_encode(&bytes), s);
    }
    if let Some(path) = safe_return_to(s) {
        assert!(path.starts_with('/') && !path.starts_with("//"));
    }
});
