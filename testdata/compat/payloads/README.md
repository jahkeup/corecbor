# User-Provided Compatibility Payloads

Drop `.json` files in this directory to add ad-hoc CBOR payloads for
compatibility testing. Each file describes a CBOR payload and its
expected decode behavior.

## File format

Each file is a JSON object:

```json
{
  "name": "my-device-telemetry-envelope",
  "description": "Telemetry payload from XYZ firmware v2.3",
  "source": "captured from production device 2026-05-15",
  "hex": "a26568656c6c6f65776f726c64636167651819",
  "expect": {
    "mode": "decode_ok",
    "type": "map",
    "keys": ["hello", "age"],
    "notes": "text-keyed map with text + uint values"
  }
}
```

## Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Short identifier for the payload |
| `description` | no | Human-readable context |
| `source` | no | Where the payload came from (device, library, capture tool) |
| `hex` | yes | The CBOR payload as a hex string (no `0x` prefix) |
| `expect.mode` | yes | One of: `decode_ok`, `decode_error`, `strict_error` |
| `expect.type` | if decode_ok | Expected top-level CBOR type: `uint`, `negint`, `bytes`, `text`, `array`, `map`, `tag`, `bool`, `null`, `undefined`, `float` |
| `expect.error` | if *_error | Expected error substring (e.g., `"truncated"`, `"non-shortest"`) |
| `expect.keys` | no | For maps: expected key values (for quick structural validation) |
| `expect.length` | no | For arrays/maps: expected element/pair count |
| `expect.tag_id` | no | For tags: expected outer tag number |
| `expect.re_encode_hex` | no | If set, the canonical re-encoding must match this hex (for round-trip testing) |
| `expect.notes` | no | Free-form notes about what this tests |

## Modes

- **`decode_ok`**: The payload decodes successfully with the forgiving decoder. The `type` field specifies what the decoded value should be.
- **`decode_error`**: The payload is malformed and MUST produce a decode error (even forgiving mode rejects it). The `error` field is a substring of the expected error.
- **`strict_error`**: The payload decodes with the forgiving decoder but MUST fail with `StrictDecoder`. The `error` field is a substring of the strict-mode error.

## Examples

### A simple map produced by another library

```json
{
  "name": "fxamacker-simple-map",
  "source": "fxamacker/cbor v2 CoreDetEnc",
  "hex": "a2616101616202",
  "expect": {
    "mode": "decode_ok",
    "type": "map",
    "length": 2,
    "re_encode_hex": "a2616101616202"
  }
}
```

### Non-shortest encoding (quirky producer)

```json
{
  "name": "legacy-device-nonshortest-uint",
  "description": "Older device encodes small integers in 2 bytes",
  "source": "captured from legacy sensor firmware",
  "hex": "1805",
  "expect": {
    "mode": "strict_error",
    "error": "shortest"
  }
}
```

### Truncated payload

```json
{
  "name": "truncated-capture",
  "description": "Partial capture due to connection drop",
  "hex": "a261",
  "expect": {
    "mode": "decode_error",
    "error": "unexpected end"
  }
}
```

## Running

```bash
make compat
```

This runs all compatibility tests including user-provided payloads.
Payload files are auto-discovered from this directory.
