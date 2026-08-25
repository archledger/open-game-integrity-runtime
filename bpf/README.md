# BPF/LSM experimental workstream

No BPF program should be added until a protected security property, policy semantics, evidence claim, noninterference requirement, and bypass test corpus are already defined.

Future BPF-LSM programs must be:

- session-scoped;
- small and publicly reviewable;
- measured and versioned;
- GPL-compatible;
- deny-by-property rather than process-scanning;
- accompanied by bypass and unrelated-process tests;
- removable when the protected session ends.

BPF is not the root of trust and is not an unrestricted anti-cheat driver.
