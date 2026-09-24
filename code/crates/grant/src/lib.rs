//! Identity and grant tokens (Internal Grant JWT, M3): a strict compact JWS
//! parser, RS256 verification, and OIDC identity-token checks (runner OIDC
//! in CI). Nothing here fetches keys; the daemon does.

pub mod jwt;
pub mod oidc;
