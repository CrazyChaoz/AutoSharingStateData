
# Overview

## Initialize the Messaging Client
Create a MessagingClient by specifying a cache/data directory. This will bootstrap a Tor client, load or create local and shared state, and prepare for onion service operations.


## Onion Service Management
Use onion_service_from_sk to start an onion service from a secret key, or let the client generate one. The onion address is used as your identity and endpoint.


## Document Collaboration
Create or load collaborative documents using create_document or get_document.
Use set_value and get_value on CollaborativeDocument to modify or read document data.
Synchronize documents with peers using sync_document, which sends changes to allowed onion addresses.

## State Management
Use add_allowed_onion_address to control which peers can sync with you.
Shared state and local data are automatically persisted to disk.


## Messaging
Send messages or data to other onion addresses using send_message or send_base64_data.
Messages are signed and sent over HTTP via Tor.

## Security
All communication is routed through Tor.
Ed25519 signatures are used for message authenticity.
Only allowed onion addresses can sync documents.

# Example Usage

```rust

use auto_merged_state_data::{generate_key, AutoSharedDocument};


let doc:AutoSharedDocument<String,String> = AutoSharedDocument::new("./test_cache1", [42u8; 32]);

let partneraddress = "partneraddress.onion".to_string();
doc.add_allowed_onion_address(partneraddress.clone()).unwrap();
doc.set_value("key", "value".to_string()).unwrap();
let _ = doc.sync_document();

```