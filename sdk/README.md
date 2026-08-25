# OGIR SDK

The public SDK is a narrow C ABI so proprietary games, C++, Rust, C#, Unity, Unreal, and other environments can integrate without embedding verifier or TPM logic.

The client API must never expose an authoritative local `IsTrusted()` result. It transports a publisher challenge, receives an opaque publisher-signed permit, and supports proof of possession of the attested session key.

`include/ogir.h` is an experimental shape only. No ABI is frozen.
