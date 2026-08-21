#![no_std]

//! Stateless Ed25519 verification utilities for Solana programs.
//!
//! This crate contains the reusable verifier used by
//! `solana-ed25519-program`. Programs can also depend on it directly to verify
//! Ed25519 signatures without invoking the standalone verifier program.
//!
//! By default the verifier performs ZIP-215 verification with canonical `S`.
//! The variant can be selected via [`VerificationCriteria`] and
//! [`Ed25519Verifier::with_criteria`].

#[cfg(feature = "instruction")]
extern crate alloc;

mod config;
pub mod constants;
mod error;
#[cfg(feature = "instruction")]
pub mod instruction;
mod points;
mod scalar;
mod verifier;

pub use config::VerificationCriteria;
pub use error::Ed25519VerifyError;
#[cfg(feature = "instruction")]
pub use instruction::verify;
pub use verifier::Ed25519Verifier;
