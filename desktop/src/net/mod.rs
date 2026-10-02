//! Network layer: interface discovery and the UDP transport.

pub mod interfaces;
pub mod transport;

pub use interfaces::{IfaceTarget, discover, glob_match, interface_allowed};
pub use transport::UdpTransport;
