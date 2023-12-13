# nillion-take-home

## Instructions

We recommend to run the current demo, using docker. The first step is to set up the necessary variables in an `.env`. We include an
example of such in `.env.example`. Please copy its contents to the actual `.env` file and run

`$ docker-compose up --build`

This will start both client and server containers. The client container can be accessed using a bash session by running

`$ docker exec -it <container-id> /bin/bash`

While in it, the user should change directory to

`$ cd client`

and then run 

`./target/release/client register --name <NAME> --password <PASSWORD>`

to make a user registration, with appropriate name and password. To then authenticate into the server, one simple runs

`./target/release/client login --name <NAME> --password <PASSWORD>`

## Project description

This projects implements a Chaum-Pedersen ZKP protocol for client-server authentication. The project is divided into three main repositories.

1. The `chaum-pedersen` implements the logic pertaining to the actual Chaum-Pedersen protocol, itself. Our implementation
relies on exponentiation methods, modulo a large (256 bit) prime `p`, and two subgroup of order `q` generators `g` and `h`.
We rely on `BigInt`, from the `num-bigint` rust crate, to handle arithmetic module large 256-bit prime fields. 
We have implemented unit tests to check for the correctness of the protocol, both in case of success (prover is honest) and
in case of improper use of the protocol (prover is cheating). 

2. The `client` crate implements all the logic related to the client. We rely on tonic to connect to the authentication server,
using the gRPC messaging protocol. Currently, our client logic is fairly simple, it receives commands and parameters from the
command line and makes the gRPC requests to the server.

3. The `server` crate contains the server logic. The server logic uses tonic in a crucial way to handle gRPC requests.
Moreover, it contains a proper state that keeps tracks of the state of each user, its associated challenges (per authentication id)
and the existing sessions per user. Moreover, the server logic makes crucial use of the Chaum-Pedersen logic, to produce
challenges and verify user authentication. We further added a complete suite of unit tests to evaluate the correctness of
our implementation.

## Further security considerations

We tried our best to make the protocol as secure as possible, as in a real production environment. Therefore, we never share user
secrets, instead we share the associated hashes. We are also mindful of memory leaks for user passwords. Therefore, we use the `Zeroize`
crate to zeroize memory whenever a password has been used and can be safely zeroized.





# Nillion Take-Home Assignment

## Instructions

For the best experience with this demo, we recommend using Docker. Start by setting up the necessary environment variables in an `.env` file. An example configuration is provided in `.env.example`. Copy the contents of `.env.example` into `.env`, then execute the following command:

```bash
$ docker-compose up --build
```

This command initializes and starts both the client and server containers. To access the client container with a bash session, use:

```bash
$ docker exec -it <container-id> /bin/bash
```

Inside the bash session, navigate to the client directory:

```bash
$ cd client
```

To register a new user, execute:

```bash
./target/release/client register --name <NAME> --password <PASSWORD>
```

Replace `<NAME>` and `<PASSWORD>` with the desired username and password. To authenticate with the server, run:

```bash
./target/release/client login --name <NAME> --password <PASSWORD>
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