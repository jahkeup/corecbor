# Cross-Library Compatibility Fixtures

This directory documents the compatibility test vectors used in
`compat_test.go`. Each fixture is a pre-computed CBOR byte sequence that
a reference implementation is known to produce for a given logical value
in deterministic/canonical mode.

## How Fixtures Were Generated

The hex vectors in `compat_test.go` were produced and verified using:

1. **fxamacker/cbor v2** (Go) — `EncMode` configured with
   `Sort: SortBytewiseLexical` (Core Deterministic per RFC 8949 §4.2.1).
   This is the primary reference for Go ecosystem compatibility.

2. **cbor.me** diagnostic tool — the web-based CBOR diagnostic tool at
   https://cbor.me/ was used to validate hex ↔ diagnostic notation for
   each test vector.

3. **cbor2** (Python) — `cbor2.dumps(value, canonical=True)` was used as
   a cross-language verification source.

4. **RFC 8949 Appendix A** — test vectors from the specification itself.

## How to Regenerate / Validate Fixtures

### Using fxamacker/cbor (Go)

```go
package main

import (
    "encoding/hex"
    "fmt"
    "github.com/fxamacker/cbor/v2"
)

func main() {
    em, _ := cbor.CoreDetEncOptions().EncMode()
    // Example: encode integer 256
    b, _ := em.Marshal(uint64(256))
    fmt.Println(hex.EncodeToString(b)) // "190100"
}
```

### Using cbor2 (Python)

```python
import cbor2
from binascii import hexlify

# Example: encode integer 256
data = cbor2.dumps(256, canonical=True)
print(hexlify(data).decode())  # "190100"
```

### Using cbor-diag (Ruby gem)

```bash
gem install cbor-diag
echo '256' | diag2cbor.rb | xxd -p
# Output: 190100
```

### Using cbor.me

Visit https://cbor.me/, enter diagnostic notation in the left pane,
and read the hex encoding from the right pane.

## Adding New Fixtures

To add a new compatibility vector:

1. Choose the logical CBOR value you want to test.
2. Encode it using at least two independent implementations in their
   deterministic/canonical mode.
3. Verify both produce identical bytes.
4. Add a new entry to the `compatVectors` table in `compat_test.go` with:
   - A descriptive name
   - The `corecbor.Value` representation
   - The expected hex encoding
   - A note indicating which libraries confirmed this encoding
5. For "quirky" decode-only vectors (non-canonical encodings), add to
   the `quirkyVectors` table with a note about which library/encoder
   produces that particular encoding.

## Key Sorting (Core Deterministic)

Per RFC 8949 §4.2.1, Core Deterministic map key sorting is:
bytewise lexicographic comparison of the encoded key bytes. This means:

- Shorter encoded keys sort before longer ones (since a prefix byte
  that encodes length will be smaller)
- Within same-length encodings, byte-by-byte comparison applies

Example sort order: `0x00` (uint 0) < `0x1864` (uint 100) < `0x20`
(negint -1) < `0x6161` (text "a") < `0x626161` (text "aa")

## References

- RFC 8949: https://www.rfc-editor.org/rfc/rfc8949
- fxamacker/cbor: https://github.com/fxamacker/cbor
- cbor2 (Python): https://github.com/agronholm/cbor2
- cbor.me: https://cbor.me/
- cbor-diag: https://github.com/cabo/cbor-diag
