//! Identity and grant tokens (Internal Grant JWT, M3): a strict compact JWS
//! parser, RS256 verification, OIDC identity-token checks (runner OIDC in
//! CI, `broker login`) and the device-flow messages (RFC 8628). Nothing
//! here does I/O; the daemon does.

pub mod device;
pub mod jwt;
pub mod oidc;
