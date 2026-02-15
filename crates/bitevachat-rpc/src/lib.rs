//! Local gRPC server for Bitevachat.
//!
//! Exposes node functionality via gRPC over Unix socket (localhost only by
//! default). Services: Wallet, Message, Contact, Group, Node. Remote access
//! requires mTLS + API token authentication.
