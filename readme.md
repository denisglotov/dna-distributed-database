# A simulation of a distributed DNA database

![Build and tests](https://github.com/denisglotov/dna-distributed-database/actions/workflows/rust.yml/badge.svg)

This project simulates a distributed DNA database using Rust.

Generate keys:

```bash
cargo run --bin key gen --key-info node-1
```

Run tests:

```bash
cargo test
```

Run the server:

```bash
RUST_LOG=debug cargo run
```
:point_right: For test keys of users and nodes, see the [config](./config) directory.


Query node state from node #3:

```bash
curl -X GET http://localhost:3000/api/3/query 
    -H "Content-Type: application/json" 
    -d '{"user_public_key": "8d8e59010750abe1b9ccfee89c38712133dc154abab838aa9de48f512c6642e2671b4fd148d114dd2685643b2423123c"}'
```

Request an update, send to node #3:

```bash
curl -X POST http://localhost:3000/api/3/update 
    -H "Content-Type: application/json" 
    -d '{"user_public_key": "8d8e59010750abe1b9ccfee89c38712133dc154abab838aa9de48f512c6642e2671b4fd148d114dd2685643b2423123c", "nonce": 0, "update": "ABC"}'
```
:point_right: For convenience, the server will sign the request with the private key from config.
