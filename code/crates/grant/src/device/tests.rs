use super::*;
use proptest::prelude::*;
use serde_json::json;

#[test]
fn authorization_response() {
    // The shape of RFC 8628 §3.2's example.
    let ok = json!({
        "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
        "user_code": "WDJB-MJHT",
        "verification_uri": "https://example.com/device",
        "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
        "expires_in": 1800,
        "interval": 5
    });
    let a = parse_authorization(200, ok.to_string().as_bytes()).unwrap();
    assert_eq!((a.user_code.as_str(), a.expires_in, a.interval), ("WDJB-MJHT", 1800, 5));
    assert!(!format!("{a:?}").contains("GmRhm"), "the device code stays out of Debug");
    let mut no_interval = ok.clone();
    no_interval.as_object_mut().unwrap().remove("interval");
    assert_eq!(parse_authorization(200, no_interval.to_string().as_bytes()).unwrap().interval, DEFAULT_INTERVAL);
    for (k, v) in [
        ("device_code", json!("")),
        ("user_code", json!("has space")),
        ("verification_uri", json!("http://example.com/device")),
        ("verification_uri_complete", json!("javascript:alert(1)")),
        ("expires_in", json!(0)),
        ("interval", json!(0)),
        ("interval", json!("5")),
    ] {
        let mut bad = ok.clone();
        bad[k] = v;
        assert!(parse_authorization(200, bad.to_string().as_bytes()).is_err(), "{k}");
    }
    let e = parse_authorization(400, br#"{"error":"invalid_client","error_description":"secret stuff"}"#);
    assert_eq!(e.unwrap_err(), DeviceError::Refused("invalid_client".into()));
    assert_eq!(parse_authorization(500, b"<html>").unwrap_err(), DeviceError::Status(500));
}

#[test]
fn token_responses() {
    let e = |code: &str| format!(r#"{{"error":"{code}"}}"#).into_bytes();
    assert_eq!(parse_token_response(400, &e("authorization_pending")).unwrap(), Poll::Pending);
    assert_eq!(parse_token_response(400, &e("slow_down")).unwrap(), Poll::SlowDown);
    assert_eq!(parse_token_response(400, &e("access_denied")).unwrap(), Poll::Denied);
    assert_eq!(parse_token_response(400, &e("expired_token")).unwrap(), Poll::Expired);
    assert_eq!(
        parse_token_response(400, &e("invalid_grant")).unwrap_err(),
        DeviceError::Refused("invalid_grant".into())
    );
    assert_eq!(parse_token_response(400, &e("<script>")).unwrap_err(), DeviceError::Refused("script".into()));
    let ok =
        br#"{"access_token":"at","token_type":"Bearer","id_token":"a.b.c","refresh_token":"rt-1","expires_in":3600}"#;
    let Poll::Tokens(t) = parse_token_response(200, ok).unwrap() else { panic!() };
    assert_eq!((t.id_token.as_str(), t.refresh_token.as_deref().map(|s| s.as_str())), ("a.b.c", Some("rt-1")));
    assert!(!format!("{t:?}").contains("a.b.c") && !format!("{t:?}").contains("rt-1"));
    assert_eq!(parse_token_response(200, br#"{"access_token":"at"}"#).unwrap_err(), DeviceError::Field("id_token"));
    assert_eq!(next_interval(5, &Poll::SlowDown), 10);
    assert_eq!(next_interval(5, &Poll::Pending), 5);
    assert_eq!(
        form(&[("grant_type", GRANT_TYPE), ("scope", "openid groups")]),
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&scope=openid%20groups"
    );
}

proptest! {
    /// Never panics on any status or body; errors never echo a value.
    #[test]
    fn parsers_are_total(status in 100u16..600, body in proptest::collection::vec(any::<u8>(), 0..300)) {
        let _ = parse_authorization(status, &body);
        if let Err(DeviceError::Refused(c)) = parse_token_response(status, &body) {
            prop_assert!(c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
        }
    }

    /// A slow_down never shortens the interval.
    #[test]
    fn intervals_only_grow(i in 1u64..600, slow in any::<bool>()) {
        let p = if slow { Poll::SlowDown } else { Poll::Pending };
        prop_assert!(next_interval(i, &p) >= i);
    }
}
