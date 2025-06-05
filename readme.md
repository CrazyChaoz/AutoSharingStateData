# auto-merged-state-data

A Rust library for collaborative document editing and secure messaging over Tor hidden services. It provides automatic state synchronization, peer management, and secure communication using Ed25519 signatures.

## Features
- **Collaborative Document Editing**: Share and synchronize state between peers using Automerge and Autosurgeon.
- **Secure Messaging**: All communication is routed through Tor and authenticated with Ed25519 signatures.
- **Peer Management**: Control which onion addresses are allowed to sync with you.
- **Persistent State**: Shared and local state are automatically saved to disk.

## Getting Started

### Add to Cargo.toml
```toml
[dependencies]
auto-merged-state-data = "<latest-version>"
```

### Example Usage
```rust
use auto_merged_state_data::{generate_key, AutoSharedDocument};

// Generate a new secret key for your onion service
let secret_key = generate_key();

// Create a new collaborative document (shared state)
let doc: AutoSharedDocument<String, String> = AutoSharedDocument::new("./test_cache1", secret_key);

// Add a peer's onion address to the allowed list
let partner_address = "partneraddress.onion".to_string();
doc.add_allowed_onion_address(partner_address.clone()).unwrap();

// Set a value in the shared state
doc.set_value("key", "value".to_string()).unwrap();

// Synchronize the document with all allowed peers
doc.sync_document().unwrap();
```

## API Overview

### Key Types
- `AutoSharedDocument<SharedDataType, LocalDataType>`: Main struct for managing shared and local state, Tor client, and onion service.
- `SharedState<T>`: Represents the shared, synchronized state (allowed onion addresses and data).
- `LocalData<T>`: Represents local-only data (private key and additional local data).

### Main Methods
- `AutoSharedDocument::new(cache_dir, secret_key)`: Create a new document and onion service.
- `add_allowed_onion_address(address)`: Allow a peer to sync with you.
- `set_value(key, value)`: Set a value in the shared state.
- `set_local_value(key, value)`: Set a value in the local-only state.
- `sync_document()`: Send the current shared state to all allowed peers.
- `get_own_onion_address()`: Get your onion address (identity).

### Security
- All communication is routed through Tor hidden services.
- Ed25519 signatures are used for message authenticity.
- Only allowed onion addresses can sync documents with you.

### Persistence
- Shared state is saved to `shared_state.json` in the cache directory.
- Local-only data (including private key) is saved to `local_only.json`.

## Testing

The library includes tests for state roundtrips, onion address generation, and document synchronization between two peers. Run tests with:

```sh
cargo test
```

## License

EUPL - European Union Public License v1.2


