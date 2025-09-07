# A simulation of a distributed DNA database

![Build and tests](https://github.com/denisglotov/dna-distributed-database/actions/workflows/rust.yml/badge.svg)

This project simulates a distributed DNA database using Rust.

## Features:

1. BLS cryptograpy scheme. Multiple node ACK signatures are aggregated into a single one to be sent as a Certificate.
2. Pluggable network implementaion `MockNetwork` that implements trait `Network` and can be easily replaced with a real implementation.
3. CLI tool `key` for crypto key generation.
4. REST API server for sending requests and queries to nodes.
5. [Swagger UI](2) for the REST API.

## Commands:

Generate keys manually (unless the default [config](1) with 5 nodes and 5 users is sufficient):

```bash
cargo run --bin key gen --key-info node-1          # a single key
cargo run --bin key gen-config --nodes 5 --users 5 # the whole config
```

Run tests:

```bash
cargo test
```

Run the server:

```bash
RUST_LOG=debug cargo run
```
:point_right: For test keys of users and nodes, see the [config](1) directory.


Query node state from node #3:

```bash
curl -X POST http://localhost:3000/api/3/query -H "Content-Type: application/json" -d '{"user_public_key": "8d8e59010750abe1b9ccfee89c38712133dc154abab838aa9de48f512c6642e2671b4fd148d114dd2685643b2423123c"}'
```

Request an update, send to node #3:

```bash
curl -X POST http://localhost:3000/api/3/update -H "Content-Type: application/json" -d '{"user_public_key": "8d8e59010750abe1b9ccfee89c38712133dc154abab838aa9de48f512c6642e2671b4fd148d114dd2685643b2423123c", "nonce": 0, "update": "ABC"}'
```
:point_right: For convenience, the server will sign the request with the private key from config.

Alternatively use [Swagger UI](2) to interact with the API.

[1]: ./config
[2]: http://localhost:3000/swagger-ui/

## Still to do:

1. Proper DNA diff merging. Currently updates simply overwrite the previous value.
2. Clean up pending requests and votings from the node memory.
3. Add mempool to save legitimate requests with higher nonce than expected.
4. Use real networking (e.g. based on libp2p) instead of `MockNetwork`.

