//! # auto-merged-state-data
//!
//! A library for collaborative document editing and secure messaging over Tor hidden services.
//!
//! ## Example Usage
//!
//! ```rust
//! use auto_merged_state_data::{generate_key, AutoSharedDocument};
//!
//!
//! let doc:AutoSharedDocument<String,String> = AutoSharedDocument::new("./test_cache1", [42u8; 32]);
//!
//! let partneraddress = "partneraddress.onion".to_string();
//!
//! doc.add_allowed_onion_address(partneraddress.clone()).unwrap();
//!
//! doc.set_value("key", "value".to_string()).unwrap();
//!
//! let _ = doc.sync_document();
//! ```
//!

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use automerge::{self, AutoCommit};
use autosurgeon::{hydrate, reconcile, Hydrate, Reconcile};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures::{Stream, StreamExt};
use futures_util::task::SpawnExt;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{header, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use log::{error, info};
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{self};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::Error;
use std::panic;
use std::path::Path;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_llcrypto::pk::ed25519::ExpandedKeypair;
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::{PreferredRuntime, ToplevelBlockOn};

/// Represents the shared state that can be synchronized between peers.
///
/// This struct is used to manage the list of allowed onion addresses and custom data
/// that can be shared between peers in a collaborative document editing system.
///
/// # Type Parameters
/// - `T`: The type of data stored in the shared state. Must implement `Reconcile`, `Hydrate`, and `Clone`.
#[derive(Debug, Clone, Serialize, Deserialize, Reconcile, Hydrate, PartialEq)]
pub struct SharedState<T: Reconcile + Hydrate + Clone> {
    /// List of allowed onion addresses to sync with.
    pub allowed_onion_addresses: Vec<String>,
    /// Custom data that can be stored in the shared state.
    pub data: HashMap<String, T>,
}

impl<T: Reconcile + Hydrate + Clone> SharedState<T> {
    /// Creates a new instance of `SharedState` with empty allowed onion addresses and data.
    ///
    /// # Returns
    /// A new `SharedState` instance.
    pub fn new() -> Self {
        SharedState {
            allowed_onion_addresses: Vec::new(),
            data: HashMap::new(),
        }
    }
}

/// Represents local-only data that is not synchronized with peers.
///
/// This struct is used to manage private keys and additional local-only data
/// in this collaborative document editing system.
///
/// # Type Parameters
/// - `LocalDataType`: The type of data stored in the additional data map. Must implement
///   `Serialize`, `Clone`, and `Debug`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalData<LocalDataType>
where
    LocalDataType: Serialize + Clone + std::fmt::Debug,
{
    /// The private key for the onion service.
    /// This key is used for secure communication and identity management.
    pub private_key: Option<Vec<u8>>,

    /// Additional local-only data that is specific to the local instance.
    /// This data is stored in a `BTreeMap` with string keys and values of type `LocalDataType`.
    pub additional_data: BTreeMap<String, LocalDataType>,
}

impl<LocalDataType> LocalData<LocalDataType>
where
    LocalDataType: Serialize + DeserializeOwned + Clone + std::fmt::Debug + Sync,
{
    /// Creates a new instance of `LocalData` with no private key and an empty additional data map.
    ///
    /// # Returns
    /// A new `LocalData` instance.
    pub fn new() -> Self {
        LocalData {
            private_key: None,
            additional_data: BTreeMap::new(),
        }
    }
}

/// Represents a document that supports collaborative editing and secure messaging.
///
/// This struct combines shared state synchronization and local-only data management.
/// It uses Tor for secure communication and Autosurgeon for state reconciliation.
///
/// # Type Parameters
/// - `SharedDataType`: The type of data stored in the shared state. Must implement
///   `Reconcile`, `Hydrate`, `Clone`, `Serialize`, `DeserializeOwned`, `Debug`, and `Sync`.
/// - `LocalDataType`: The type of data stored in the local-only state. Must implement
///   `DeserializeOwned`, `Serialize`, `Clone`, `Debug`, and `Sync`.
pub struct AutoSharedDocument<
    SharedDataType: Reconcile
        + Hydrate
        + Clone
        + Serialize
        + DeserializeOwned
        + std::fmt::Debug
        + Sync,
    LocalDataType: DeserializeOwned + Serialize + Clone + std::fmt::Debug + Sync,
> {
    /// The Tor client used for secure communication.
    client: TorClient<PreferredRuntime>,

    /// The shared state that can be synchronized between peers.
    /// This state is managed using Autosurgeon and Automerge.
    shared_state: Arc<Mutex<AutoCommit>>,

    /// The local data that should not be synchronized with peers.
    /// This data is specific to the local instance and is stored in a `LocalData` struct.
    local_data: Arc<Mutex<LocalData<LocalDataType>>>,

    /// The path to the directory where data files are stored.
    /// This directory is used for caching and persistence of shared and local data.
    data_dir: String,

    /// A phantom data marker for the `SharedDataType` type parameter.
    /// This is used to ensure the type parameter is retained in the struct's type signature.
    _phantom: std::marker::PhantomData<SharedDataType>,
}

/// Implementation block for the `AutoSharedDocument` struct.
///
/// This block defines methods for managing shared and local data, syncing documents,
/// and interacting with Tor onion services.
///
/// # Type Parameters
/// - `SharedDataType`: The type of data stored in the shared state. Must implement
///   `Reconcile`, `Hydrate`, `Clone`, `Serialize`, `DeserializeOwned`, `Debug`, and `Sync`.
/// - `LocalDataType`: The type of data stored in the local-only state. Must implement
///   `DeserializeOwned`, `Serialize`, `Clone`, `Debug`, and `Sync`.
impl<SharedDataType, LocalDataType> AutoSharedDocument<SharedDataType, LocalDataType>
where
    SharedDataType: Reconcile
        + Hydrate
        + Clone
        + Serialize
        + DeserializeOwned
        + std::fmt::Debug
        + std::marker::Sync,
    LocalDataType: DeserializeOwned + Serialize + Clone + std::fmt::Debug + std::marker::Sync,
{
    /// Creates a new instance of `AutoSharedDocument` with the specified cache directory and onion address secret key.
    ///
    /// This function initializes the Tor client, sets up the local and shared state, and creates the necessary
    /// directories for caching and persistence. It also starts an onion service using the provided secret key.
    ///
    /// # Parameters
    /// - `cache_dir`: The path to the cache directory where data files will be stored.
    /// - `onion_address_secret_key`: A 32-byte secret key used to generate the onion address for the service.
    ///
    /// # Returns
    /// An instance of `AutoSharedDocument` configured with the specified parameters.
    ///
    /// # Panics
    /// - If the cache directory cannot be created.
    /// - If the Tor client configuration fails.
    /// - If the local or shared state files cannot be opened or parsed.
    pub fn new(
        cache_dir: &str,
        onion_address_secret_key: [u8; 32],
    ) -> AutoSharedDocument<SharedDataType, LocalDataType> {
        // Create the data directory if it doesn't exist
        let data_dir = format!("{}{}", cache_dir, std::path::MAIN_SEPARATOR);
        if !Path::new(&data_dir).exists() {
            fs::create_dir_all(&data_dir).expect("Failed to create data directory");
        }

        eprintln!("Starting Tor client");

        let rt = if let Ok(runtime) = PreferredRuntime::current() {
            runtime
        } else {
            PreferredRuntime::create().expect("could not create async runtime")
        };

        let mut config = TorClientConfigBuilder::from_directories(
            format!("{data_dir}arti-data"),
            format!("{data_dir}arti-cache"),
        );
        config.address_filter().allow_onion_addrs(true);

        let config = config.build().expect("error building tor config");

        let binding = TorClient::with_runtime(rt.clone()).config(config);
        let client_future = binding.create_bootstrapped();

        rt.block_on(async {
            let client = client_future.await.unwrap();

            eprintln!("Tor client started");
            info!("Tor client started");

            // Load or create local data
            let local_data_path = format!("{data_dir}local_only.json");
            let local_data = if Path::new(&local_data_path).exists() {
                let file = File::open(&local_data_path).expect("Failed to open local_only.json");
                serde_json::from_reader(file).unwrap_or_else(|_| {
                    eprintln!("Failed to parse local_only.json, creating new local data");
                    LocalData::new()
                })
            } else {
                LocalData::new()
            };

            // Load or create shared state
            let shared_state_path = format!("{data_dir}shared_state.json");

            if Path::new(&shared_state_path).exists() {
                let file =
                    File::open(&shared_state_path).expect("Failed to open shared_state.json");
                serde_json::from_reader(file).unwrap_or_else(|_| {
                    eprintln!("Failed to parse shared_state.json, creating new shared state");
                });
            };

            let mut shared_state = AutoCommit::new();
            shared_state = shared_state.fork().with_actor(automerge::ActorId::random());
            reconcile(&mut shared_state, &SharedState::<SharedDataType>::new()).unwrap();

            let document = AutoSharedDocument {
                client,
                shared_state: Arc::new(Mutex::new(shared_state)),
                local_data: Arc::new(Mutex::new(local_data)),
                data_dir: data_dir.to_string(),
                _phantom: Default::default(),
            };

            let onion_address = document
                .onion_service_from_sk(&onion_address_secret_key)
                .await;

            document.add_allowed_onion_address(onion_address).unwrap();

            document
        })
    }

    async fn onion_service_from_sk(&self, secret_key: &[u8]) -> String {
        let sk = <[u8; 32]>::try_from(secret_key).expect("could not convert to [u8; 32]");
        let sk = sk as ed25519_dalek::SecretKey;
        let expanded_secret_key = ed25519_dalek::hazmat::ExpandedSecretKey::from(&sk);
        let esk = <[u8; 64]>::try_from(
            [
                expanded_secret_key.scalar.to_bytes(),
                expanded_secret_key.hash_prefix,
            ]
            .concat()
            .as_slice(),
        )
        .unwrap();
        let expanded_key_pair = ExpandedKeypair::from_secret_key_bytes(esk)
            .expect("error converting to ExpandedKeypair");
        let pk = expanded_key_pair.public();

        let mut local_data = self.local_data.lock().unwrap();
        local_data.private_key = Some(secret_key.to_vec());

        let onion_address = get_onion_address(&pk.to_bytes());
        let clone_onion_address = onion_address.clone();
        let nickname = format!(
            "tor-document-{}",
            onion_address.clone().chars().take(16).collect::<String>()
        );

        let encodable_key = tor_hscrypto::pk::HsIdKeypair::from(expanded_key_pair);

        let svc_cfg = OnionServiceConfigBuilder::default()
            .nickname(nickname.clone().parse().unwrap())
            .build()
            .unwrap();

        let (onion_service, request_stream): (
            _,
            Pin<Box<dyn Stream<Item = tor_hsservice::RendRequest> + Send>>,
        ) = if let Ok((service, stream)) = self
            .client
            .launch_onion_service_with_hsid(svc_cfg.clone(), encodable_key)
        {
            (service, Box::pin(stream))
        } else {
            // This key exists; reuse it
            let (service, stream) = self
                .client
                .launch_onion_service(svc_cfg)
                .expect("error creating onion service");
            (service, Box::pin(stream))
        };
        info!(
            "onion service created: {}",
            onion_service.onion_address().unwrap()
        );
        info!("status: {:?}", onion_service.status());

        while let Some(status_event) = onion_service.status_events().next().await {
            if status_event.state().is_fully_reachable() {
                break;
            }
        }
        info!("status: {:?}", onion_service.status());

        let shared_state = self.shared_state.clone();
        let data_dir = self.data_dir.clone();

        self.client
            .clone()
            .runtime()
            .spawn(async move {
                let accepted_streams = tor_hsservice::handle_rend_requests(request_stream);

                tokio::pin!(accepted_streams);

                while let Some(stream_request) = accepted_streams.next().await {
                    info!("new stream");
                    let request = stream_request.request().clone();
                    match request {
                        IncomingStreamRequest::Begin(begin) if begin.port() == 80 => {
                            let onion_service_stream =
                                stream_request.accept(Connected::new_empty()).await.unwrap();
                            let io = TokioIo::new(onion_service_stream);

                            let shared_state = shared_state.clone();
                            let data_dir = data_dir.clone();

                            http1::Builder::new()
                                .serve_connection(
                                    io,
                                    service_fn(|request| {
                                        Self::service_function(
                                            request,
                                            shared_state.clone(),
                                            data_dir.clone(),
                                        )
                                    }),
                                )
                                .await
                                .unwrap();
                        }
                        _ => {
                            stream_request.shutdown_circuit().unwrap();
                        }
                    };
                }
                drop(onion_service);
                info!("onion service dropped");
            })
            .expect("error spawning task");

        clone_onion_address
    }

    async fn service_function(
        request: Request<Incoming>,
        shared_state: Arc<Mutex<AutoCommit>>,
        data_dir: String,
    ) -> Result<Response<String>, anyhow::Error> {
        info!("request gotten");
        let path = request.uri().path().to_string();
        let binding = request.headers().clone();
        let signature = binding.get("X-Signature-Ed25519");
        if path == "/shared_state" {
            let message = request.collect().await.unwrap().to_bytes();
            let message = String::from_utf8(message.to_vec()).expect("error parsing message");
            if let Some(signature) = signature {
                let signature = signature
                    .to_str()
                    .expect("error converting signature to string")
                    .to_string();

                let signature = base64::prelude::BASE64_STANDARD
                    .decode(signature)
                    .expect("error decoding signature from base64");

                let data: SharedState<SharedDataType> =
                    serde_json::from_str::<SharedState<SharedDataType>>(&message)
                        .map_err(|_| ())
                        .expect("error parsing message to JSON");
                let clone_data = data.clone();
                
                let mut is_from_allowed_addresses = false;

                for address in data.allowed_onion_addresses.iter() {
                    let public_key = get_public_key_from_onion_address(address);
                    if verify_signature(&message, &signature, &public_key) {
                        info!("signature verified");
                        is_from_allowed_addresses = true;
                        break;
                    }
                }

                if !is_from_allowed_addresses {
                    eprintln!("signature not from allowed addresses");
                    info!("signature not from allowed addresses");
                    return Ok::<Response<String>, anyhow::Error>(
                        Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body("Signature not from allowed addresses".to_string())?,
                    );
                }

                // Put data into a document
                let mut doc = shared_state
                    .lock()
                    .unwrap()
                    .fork()
                    .with_actor(automerge::ActorId::random());
                reconcile(&mut doc, &clone_data).unwrap();

                shared_state
                    .lock()
                    .unwrap()
                    .merge(&mut doc)
                    .expect("TODO: panic message");

                let shared_state = shared_state.lock().unwrap().clone();
                let hydrated_state: SharedState<SharedDataType> = hydrate(&shared_state).unwrap();
                // Save the shared state to a file
                Self::save_shared_state_inner(&hydrated_state, data_dir.clone()).unwrap();

                eprintln!("Shared state updated: {:?}", clone_data);
                info!("Shared state updated: {:?}", clone_data);
            }
        } else {
            info!("unknown path");
        }
        Ok::<Response<String>, anyhow::Error>(
            Response::builder()
                .status(StatusCode::OK)
                .body("Shared state received".to_string())?,
        )
    }

    async fn send_message_inner(&self, message: &str, recipient: &str, endpoint: &str) -> String {
        let url: Uri = Uri::from_str(recipient).expect("error parsing recipient URL");
        let host = url.host().unwrap();

        eprintln!("host parsed: {host}");
        info!("host parsed: {host}");

        let Ok(stream) = self.client.connect((format!("{host}.onion"), 80)).await else {
            eprintln!("could not connect to recipient");
            info!("could not connect to recipient");
            return "".to_string();
        };

        eprintln!("stream connected to {host}");
        info!("stream connected to {host}");

        let (mut request_sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .unwrap();

        // spawn a task to poll the connection and drive the HTTP state
        tokio::spawn(async move {
            connection.await.unwrap();
        });

        let sk = <[u8; 32]>::try_from(self.local_data.lock().unwrap().private_key.clone().unwrap())
            .unwrap();
        let expanded_secret_key = ed25519_dalek::hazmat::ExpandedSecretKey::from(&sk);
        let esk = <[u8; 64]>::try_from(
            [
                expanded_secret_key.scalar.to_bytes(),
                expanded_secret_key.hash_prefix,
            ]
            .concat()
            .as_slice(),
        )
        .unwrap();
        let key = ExpandedKeypair::from_secret_key_bytes(esk).unwrap();

        let resp = request_sender
            .send_request(
                Request::builder()
                    .uri(endpoint)
                    .header("Host", host)
                    .header(
                        "X-Signature-Ed25519",
                        base64::prelude::BASE64_STANDARD
                            .encode(key.sign(message.as_bytes()).to_bytes()),
                    )
                    .method("GET")
                    .body(message.to_string())
                    .unwrap(),
            )
            .await
            .unwrap();

        if let Some(content_type) = resp.headers().get(header::CONTENT_TYPE) {
            // Convert header value to a string
            if let Ok(content_type_str) = content_type.to_str() {
                eprintln!("Content-Type: {content_type_str}");
                info!("Content-Type: {content_type_str}");
            } else {
                eprintln!("Content-Type is not a valid string");
                info!("Content-Type is not a valid string");
            }
        } else {
            eprintln!("Content-Type header is missing");
            info!("Content-Type header is missing");
        }
        match resp.status().as_u16() {
            200 => {
                String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().into())
                    .expect("error unwrapping response into string")
                //"status 200 but no body".to_string()
            }
            _ => {
                format!("error: status {}", resp.status().as_u16())
            }
        }
    }

    /// Saves the shared state to a file.
    ///
    /// This method locks the shared state, hydrates it into a `SharedState` instance,
    /// and then delegates the saving process to the `save_shared_state_inner` function.
    ///
    /// # Returns
    /// - `Ok(())`: If the shared state is successfully saved.
    /// - `Err(std::io::Error)`: If an error occurs during the saving process.
    pub fn save_shared_state(&self) -> Result<(), std::io::Error> {
        let document = self.shared_state.lock().unwrap().clone();
        let shared_state: SharedState<SharedDataType> = hydrate(&document).unwrap();
        Self::save_shared_state_inner(&shared_state, self.data_dir.clone())
    }

    /// Saves the shared state to a file at the specified directory.
    ///
    /// This function creates a file named `shared_state.json` in the given directory
    /// and writes the serialized shared state into it.
    ///
    /// # Parameters
    /// - `shared_state`: A reference to the `SharedState` instance to be saved.
    /// - `data_dir`: The directory path where the file will be created.
    ///
    /// # Returns
    /// - `Ok(())`: If the shared state is successfully saved.
    /// - `Err(std::io::Error)`: If an error occurs during file creation or writing.
    fn save_shared_state_inner(
        shared_state: &SharedState<SharedDataType>,
        data_dir: String,
    ) -> Result<(), std::io::Error> {
        let shared_state_path = format!("{}shared_state.json", data_dir);
        let file = File::create(&shared_state_path)?;
        serde_json::to_writer_pretty(file, shared_state)?;
        Ok(())
    }

    /// Saves the local-only data to a file.
    ///
    /// This method locks the local data, clones it, and writes it to a file named `local_only.json`
    /// in the directory specified by `data_dir`. The data is serialized in a pretty JSON format.
    ///
    /// # Returns
    /// - `Ok(())`: If the local data is successfully saved.
    /// - `Err(std::io::Error)`: If an error occurs during file creation or writing.
    pub fn save_local_data(&self) -> Result<(), std::io::Error> {
        let local_data_path = format!("{}local_only.json", self.data_dir);
        let local_data = self.local_data.lock().unwrap().clone();
        let file = File::create(&local_data_path)?;
        serde_json::to_writer_pretty(file, &local_data)?;
        Ok(())
    }

    /// Adds an onion address to the list of allowed addresses and saves the shared state.
    ///
    /// This method updates the shared state by adding the specified onion address to the list
    /// of allowed addresses. It uses Autosurgeon to reconcile the updated state with the document
    /// and then saves the updated shared state to persistent storage.
    ///
    /// # Parameters
    /// - `address`: The onion address to be added to the list of allowed addresses.
    ///
    /// # Returns
    /// - `Ok(())`: If the onion address is successfully added and the shared state is saved.
    /// - `Err(std::io::Error)`: If an error occurs during the saving process.
    pub fn add_allowed_onion_address(&self, address: String) -> Result<(), std::io::Error> {
        let mut forked_doc = self
            .shared_state
            .lock()
            .unwrap()
            .fork()
            .with_actor(automerge::ActorId::random());
        let mut hydrated_state: SharedState<SharedDataType> = hydrate(&forked_doc).unwrap();
        hydrated_state.allowed_onion_addresses.push(address);
        reconcile(&mut forked_doc, &hydrated_state).unwrap();
        self.shared_state
            .lock()
            .unwrap()
            .merge(&mut forked_doc)
            .expect("TODO: panic message");
        self.save_shared_state()
    }

    /// Checks if the specified onion address is allowed to sync.
    ///
    /// This method examines the shared state to determine whether the given onion address
    /// is included in the list of allowed addresses.
    ///
    /// # Parameters
    /// - `address`: A string slice representing the onion address to check.
    ///
    /// # Returns
    /// - `true`: If the onion address is allowed to sync.
    /// - `false`: If the onion address is not allowed to sync.
    pub fn is_onion_address_allowed(&self, address: &str) -> bool {
        let locked_doc = self.shared_state.lock().unwrap().clone();
        let hydrated_state: SharedState<SharedDataType> = hydrate(&locked_doc).unwrap();
        hydrated_state
            .allowed_onion_addresses
            .contains(&address.to_string())
    }

    /// Sets a value in the shared state.
    ///
    /// This method locks the shared state, hydrates it into a `SharedState` instance,
    /// and inserts the specified key-value pair into the `data` field of the shared state.
    /// The updated state is then reconciled with the document and saved to persistent storage.
    ///
    /// # Parameters
    /// - `key`: A string slice representing the key to be added or updated in the shared state.
    /// - `value`: The value of type `SharedDataType` to be associated with the specified key.
    ///
    /// # Returns
    /// - `Ok(())`: If the value is successfully set and the shared state is saved.
    /// - `Err(std::io::Error)`: If an error occurs during the saving process.
    pub fn set_value(&self, key: &str, value: SharedDataType) -> Result<(), Error> {
        let mut locked_doc = self
            .shared_state
            .lock()
            .unwrap()
            .fork()
            .with_actor(automerge::ActorId::random());
        let mut hydrated_state: SharedState<SharedDataType> = hydrate(&locked_doc).unwrap();
        hydrated_state.data.insert(key.parse().unwrap(), value);
        reconcile(&mut locked_doc, &hydrated_state).unwrap();
        self.shared_state
            .lock()
            .unwrap()
            .merge(&mut locked_doc)
            .expect("TODO: panic message");
        self.save_shared_state()
    }
    /// Sets a local-only value that should not be synchronized with peers.
    ///
    /// This method updates the `additional_data` field in the local-only data
    /// by inserting the specified key-value pair. The updated local data is then
    /// saved to persistent storage.
    ///
    /// # Parameters
    /// - `key`: A string slice representing the key to be added or updated in the local-only data.
    /// - `value`: The value of type `LocalDataType` to be associated with the specified key.
    ///
    /// # Returns
    /// - `Ok(())`: If the value is successfully set and the local data is saved.
    /// - `Err(std::io::Error)`: If an error occurs during the saving process.
    pub fn set_local_value(&self, key: &str, value: LocalDataType) -> Result<(), Error> {
        let mut local_data = self.local_data.lock().unwrap();
        local_data.additional_data.insert(key.to_string(), value);
        self.save_local_data()
    }

    /// Get the private key for the onion service
    fn get_private_key(&self) -> Option<Vec<u8>> {
        let local_data = self.local_data.lock().unwrap();
        local_data.private_key.clone()
    }

    /// Synchronizes the document with other peers.
    ///
    /// This method serializes the current shared state into a JSON string and sends it to all
    /// allowed onion addresses. It uses the `send_message_inner` method to send the data
    /// asynchronously to each peer. If the synchronization fails for any peer, an error is returned.
    ///
    /// # Returns
    /// - `Ok(())`: If the document is successfully synchronized with all peers.
    /// - `Err(String)`: If an error occurs during serialization or synchronization.
    ///
    /// # Errors
    /// - Returns an error if the shared state cannot be serialized into JSON.
    /// - Returns an error if the synchronization fails for one or more peers.
    pub fn sync_document(&self) -> Result<(), String> {
        // Serialize the sync message
        let document = self.shared_state.lock().unwrap().clone();
        let shared_state: SharedState<SharedDataType> = hydrate(&document).unwrap();

        let sync_message_json = match serde_json::to_string(&shared_state) {
            Ok(json) => json,
            Err(e) => return Err(format!("Failed to serialize sync message: {}", e)),
        };

        let mut any_failed = false;
        for peer_address in shared_state.allowed_onion_addresses {
            // Send the sync message to the peer
            let runtime = self.client.runtime().clone();
            runtime.block_on(async {
                let response = self
                    .send_message_inner(&sync_message_json, &*peer_address, "/shared_state")
                    .await;
                if response.is_empty() {
                    any_failed = true;
                    return Err(format!("Failed to send sync message to {}", peer_address));
                }
                Ok(())
            })?;
        }

        if any_failed {
            return Err("Failed to send shared state to one or more peers".to_string());
        }

        Ok(())
    }

    /// Retrieves the onion address of this node.
    ///
    /// This method calculates the onion address using the private key stored in the local data.
    /// If the private key is not set, it logs a message and returns an empty string.
    ///
    /// # Returns
    /// A `String` containing the onion address of this node. If the private key is not set,
    /// an empty string is returned.
    ///
    /// # Panics
    /// - If the private key cannot be converted to a `[u8; 32]` array.
    /// - If the expanded secret key cannot be converted to a `[u8; 64]` array.
    /// - If the expanded key pair cannot be created from the secret key bytes.
    pub fn get_own_onion_address(&self) -> String {
        // If we have a private key, use it to get the onion address
        let local_data = self.local_data.lock().unwrap();
        let private_key = match local_data.private_key {
            Some(ref key) => key,
            None => {
                info!("No private key set for this service");
                return String::new();
            }
        };
        let sk = <[u8; 32]>::try_from(private_key.as_slice())
            .expect("could not convert private key to [u8; 32]");
        let expanded_secret_key = ed25519_dalek::hazmat::ExpandedSecretKey::from(&sk);
        let esk = <[u8; 64]>::try_from(
            [
                expanded_secret_key.scalar.to_bytes(),
                expanded_secret_key.hash_prefix,
            ]
            .concat()
            .as_slice(),
        )
        .expect("could not convert to [u8; 64]");
        let expanded_key_pair = ExpandedKeypair::from_secret_key_bytes(esk)
            .expect("error converting to ExpandedKeypair");
        let pk = expanded_key_pair.public();
        get_onion_address(&pk.to_bytes())
    }
}

/// Generates a new 32-byte secret key.
///
/// This function uses a random number generator to fill a 32-byte array
/// with random values, which can be used as a secret key.
///
/// # Returns
/// A `[u8; 32]` array containing the generated secret key.
pub fn generate_key() -> [u8; 32] {
    let mut rng = rand::rng();
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    sk
}

/// Generates a Tor onion address from a given public key.
///
/// This function computes the onion address by performing the following steps:
/// 1. Converts the provided public key into a fixed-size array.
/// 2. Constructs a buffer containing the public key, checksum, and version.
/// 3. Calculates the checksum using the SHA3-256 hash function.
/// 4. Encodes the buffer into a base32 string to produce the onion address.
///
/// # Parameters
/// - `public_key`: A byte slice representing the public key. Must be convertible to a `[u8; 32]` array.
///
/// # Returns
/// A `String` containing the generated onion address.
///
/// # Panics
/// - If the `public_key` cannot be converted to a `[u8; 32]` array.
pub fn get_onion_address(public_key: &[u8]) -> String {
    let pub_key = <[u8; 32]>::try_from(public_key).expect("could not convert to [u8; 32]");
    let mut buf = [0u8; 35];
    pub_key.iter().copied().enumerate().for_each(|(i, b)| {
        buf[i] = b;
    });

    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(pub_key);
    h.update(b"\x03");

    let res_vec = h.finalize().to_vec();
    buf[32] = res_vec[0];
    buf[33] = res_vec[1];
    buf[34] = 3;

    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &buf).to_ascii_lowercase()
}

/// Extracts the public key from a given Tor onion address.
///
/// This function attempts to decode the onion address from base32 format and
/// truncate the resulting vector to the first 32 bytes, which represent the public key.
///
/// # Parameters
/// - `onion_address`: A string slice representing the Tor onion address.
///
/// # Returns
/// A `Vec<u8>` containing the public key extracted from the onion address. If the decoding
/// fails or an error occurs, an empty vector is returned.
///
/// # Panics
/// - If the decoding process encounters an unrecoverable error.
pub fn get_public_key_from_onion_address(onion_address: &str) -> Vec<u8> {
    panic::catch_unwind(|| {
        let mut res_vec: Vec<u8> = base32::decode(
            base32::Alphabet::Rfc4648Lower { padding: false },
            &*onion_address.to_ascii_lowercase(),
        )
        .unwrap_or_else(|| {
            eprintln!("error: {onion_address} could not convert from base32");
            Vec::<u8>::new()
        });
        res_vec.truncate(32);
        res_vec
    })
    .unwrap_or_else(|cause| {
        error!("{:?}", cause);
        Vec::<u8>::new()
    })
}

/// Verifies the signature of the given data using the provided public key.
///
/// This function attempts to verify the signature by:
/// 1. Converting the public key into a `VerifyingKey`.
/// 2. Using the `verify` method to check if the signature matches the data.
/// If the verification fails or an error occurs during the process, it returns `false`.
///
/// # Parameters
/// - `data`: A string slice representing the data to be verified.
/// - `signature`: A byte slice containing the signature to verify.
/// - `public_key`: A byte slice representing the public key used for verification.
///
/// # Returns
/// - `true`: If the signature is valid.
/// - `false`: If the signature is invalid or an error occurs.
///
/// # Panics
/// - If the `public_key` or `signature` cannot be converted to their respective types.
pub fn verify_signature(data: &str, signature: &[u8], public_key: &[u8]) -> bool {
    panic::catch_unwind(|| {
        let verifying_key =
            VerifyingKey::try_from(public_key).expect("could not convert public key");
        verifying_key
            .verify(
                data.as_bytes(),
                &Signature::try_from(signature).expect("signature bytes could not be converted"),
            )
            .is_ok()
    })
    .unwrap_or_else(|cause| {
        error!("{:?}", cause);
        false
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use automerge::AutoCommit;
    use autosurgeon::{hydrate, reconcile};

    #[test]
    fn test_shared_state_autosurgeon_roundtrip() {
        let mut doc = AutoCommit::new();
        let mut state = SharedState::new();
        state.allowed_onion_addresses.push("abc.onion".to_string());
        state.data.insert("key".to_string(), "value".to_string());

        // Reconcile into the doc
        reconcile(&mut doc, &state).unwrap();
        // Hydrate back out
        let hydrated: SharedState<String> = hydrate(&doc).unwrap();
        assert_eq!(state, hydrated);
    }

    #[test]
    fn test_shared_state_update_allowed_onion_addresses() {
        let mut doc = AutoCommit::new();
        let mut state = SharedState::new();
        state.allowed_onion_addresses.push("abc.onion".to_string());
        reconcile(&mut doc, &state).unwrap();

        // Update the state
        let mut updated_state = state.clone();
        updated_state
            .allowed_onion_addresses
            .push("def.onion".to_string());
        reconcile(&mut doc, &updated_state).unwrap();

        let hydrated: SharedState<String> = hydrate(&doc).unwrap();
        assert_eq!(updated_state, hydrated);
    }

    #[test]
    fn test_shared_state_update_data_field() {
        let mut doc = AutoCommit::new();
        let mut state = SharedState::new();
        state.data.insert("key".to_string(), "value".to_string());
        reconcile(&mut doc, &state).unwrap();

        // Update the data field
        let mut updated_state = state.clone();
        updated_state
            .data
            .insert("key2".to_string(), "value2".to_string());
        reconcile(&mut doc, &updated_state).unwrap();

        let hydrated: SharedState<String> = hydrate(&doc).unwrap();
        assert_eq!(updated_state, hydrated);
    }

    #[test]
    fn test_onion_address() {
        let pk = vec![42u8; 32];
        let onion_address = get_onion_address(&pk);
        assert_eq!(
            onion_address,
            "fivcukrkfivcukrkfivcukrkfivcukrkfivcukrkfivcukrkfivjcrid"
        );
    }

    #[test]
    fn test_start_server() {
        let client: AutoSharedDocument<String, String> = AutoSharedDocument::new(".", [42u8; 32]);
        let onion_address = client.get_own_onion_address();

        assert_eq!(
            onion_address,
            "df7wwi7bnsctfrvlza4pvtk6u6e34ddwwkjagnadtp5iwpjwrvq5bpad"
        );
    }

    #[test]
    fn test_two_documents_sync() {
        // Generate two keys for two separate documents
        let key1 = [42u8; 32];
        let key2 = generate_key();
        // Use separate cache dirs for isolation
        let cache1 = "./test_cache1";
        let cache2 = "./test_cache2";
        // Clean up any old test data
        let _ = std::fs::remove_dir_all(cache1);
        let _ = std::fs::remove_dir_all(cache2);
        // Create two documents
        let doc1: AutoSharedDocument<String, String> = AutoSharedDocument::new(cache1, key1);
        let doc2: AutoSharedDocument<String, String> = AutoSharedDocument::new(cache2, key2);
        // Get their onion addresses
        let onion1 = doc1.get_own_onion_address();
        let onion2 = doc2.get_own_onion_address();
        assert!(!onion1.is_empty());
        assert!(!onion2.is_empty());
        // Add each other's onion address to allowed list
        doc1.add_allowed_onion_address(onion2.clone()).unwrap();
        doc2.add_allowed_onion_address(onion1.clone()).unwrap();

        // Add data to each document
        doc1.set_value("from1", "hello from 1".to_string()).unwrap();
        let _ = doc1.sync_document();

        doc2.set_value("from2", "hello from 2".to_string()).unwrap();
        let _ = doc2.sync_document();

        // Reload state from disk to check persistence
        let file1 = std::fs::File::open(format!("{}/shared_state.json", cache1)).unwrap();
        let state1: SharedState<String> = serde_json::from_reader(file1).unwrap();
        let file2 = std::fs::File::open(format!("{}/shared_state.json", cache2)).unwrap();
        let state2: SharedState<String> = serde_json::from_reader(file2).unwrap();
        assert_eq!(state1.data["from1"], "hello from 1");
        assert_eq!(state1.data["from2"], "hello from 2");

        assert_eq!(state2.data["from1"], "hello from 1");
        assert_eq!(state2.data["from2"], "hello from 2");
        // Clean up test data
        // let _ = std::fs::remove_dir_all(cache1);
        // let _ = std::fs::remove_dir_all(cache2);
    }
}
