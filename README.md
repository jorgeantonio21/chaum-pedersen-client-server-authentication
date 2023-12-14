# Nillion Take-Home Assignment

## Instructions

For the best experience with this demo, we recommend using Docker. Start by setting up the necessary environment variables in an `.env` file. An example configuration is provided in `.env.example`. Copy the contents of `.env.example` into `.env`, then execute the following command:

```bash
$ docker-compose up --build
```

This command initializes and starts both the client and server containers. To access the client container with a bash session, execute on a new terminal window:

```bash
$ docker exec -it <client-container-id> /bin/bash
```

Inside the bash session, navigate to the client directory:

```bash
$ cd client
```

To register a new user, execute:

```bash
$ ./target/release/client register --name <NAME> --password <PASSWORD>
```

Replace `<NAME>` and `<PASSWORD>` with the desired username and password. To authenticate with the server, run:

```bash
$ ./target/release/client login --name <NAME> --password <PASSWORD>
```

## Project description

This project implements a Chaum-Pedersen Zero-Knowledge Proof (ZKP) protocol for client-server authentication. It is divided into three main components:

1. **Chaum-Pedersen Logic (`chaum-pedersen`):**

* This component implements the core logic of the Chaum-Pedersen protocol.
* Our implementation relies on exponentiation methods, operating modulo a large (256-bit) prime `p`, and utilizing two multiplicative subgroup generators `g` and `h` of order `q`.
* Arithmetic operations in large 256-bit prime fields are handled using the `BigInt` library from the `num-bigint` Rust crate.
* Unit tests are included to verify the protocol's correctness in scenarios of both honest and dishonest use.

2. **Client Logic (`client`):**

* This crate handles all client-side logic.
* It uses tonic for connecting to the authentication server via the gRPC messaging protocol.
* The client logic is currently straightforward, processing commands and parameters from the command line and making gRPC requests to the server.

3. **Server Logic (`server`):**

* This crate contains the server's logic.
* It crucially uses tonic to manage gRPC requests. 
* The server maintains the state of each user, tracks associated challenges (per authentication ID), and manages active user sessions. 
* The server's logic integrates with the Chaum-Pedersen protocol for generating challenges and verifying user authentication. 
* A comprehensive suite of unit tests ensures the correctness of the implementation.

## Further security considerations

We did our best to follow best practices for production environments, the implementation prioritizes security:

* User secrets are never shared directly; only associated hashes are exchanged.
* To prevent memory leaks of user passwords, the `Zeroize` crate is employed to securely erase password data from memory after use.
* In order to be able to use 256-security prime fields, we had to change the signature of the proto files, namely we replaced
`uint64` instances by `bytes`, assumed to be in big-endian form.