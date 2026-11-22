# Certificate Transparency Merkle proof vectors

Inclusion and consistency proof probes for the RFC 6962 / RFC 9162
SHA-256 Merkle tree, copied unmodified from
`github.com/transparency-dev/merkle` at commit
`75a6539d7b48af0d529236f24487d2814fd1dca7` (`testdata/inclusion`,
`testdata/consistency`). Licensed under the Apache License 2.0
(Copyright 2019 Google LLC), the same license as corecbor.

Each JSON file is one probe: a happy path, or a mutation that must fail
(`wantErr`). Hashes are base64. `TestMerkleCTVectors` runs them.

The two happy-path probes with `size1 == size2` and an empty proof
(`consistency/0/happy-path.json`,
`consistency/additional/sizes-are-equal-one-and-proof-is-empty.json`)
are rejected here on purpose: RFC 9162 §2.1.4.2 defines consistency only
for `0 < first < second` and fails an empty path, and an RFC 9942
consistency receipt has to prove a real extension.
