# example-node-manual-tls
A dummy example of TLS implementation. Reminder don't use this in production.

## Getting started
1. Generate server (self-signed) certificate (you would need openssl installed)

```sh
cd ./bin && mkdir certs && cd ./certs

# generate a private key (2048-bit RSA key)
openssl genpkey -algorithm RSA -out server-key.pem -aes256

# generate a Certificate Signing Request (CSR)
openssl req -new -key server-key.pem -out server-csr.pem

# generate a self-signed certificate valid for 365 days
openssl x509 -req -days 365 -in server-csr.pem -signkey server-key.pem -out server-cert.pem
```

2. Configure .env
```sh
# root
cp .env.example .env
```

> update `SERVER_PCERT_PASSPHRASE` with the passphrase you used during the pkey creation from step 1 above. You can also omit passphrase in the first place, by removing -aes256, but that would require some minor code changes.

3. Run the server

```sh
npm run start:server
```

3. Open a client connection

```sh
npm run connect:client
```

> Server and client are using port 3000, if that is not available for you, just pass an arg `cmd -- --port=x`, and of course make sure you start the server and connect the client on that very same port...

> You can review your server cert information via `openssl x509 -in server-cert.pem -text -noout` 

## The play (ping-pong):

Phase 1: three-way handshake, which is a process used to establish a connection between two devices on a network.

1. Alice waves to Bob.
> client send `SYN` (TCP packet containing a synchronize flag) to server, aka tries to connect to server

2. Bob waves back to Alice.
> server sends `SYN-ACK` (TCP packet containing the synchronize and acknowledge flags set) to client, aka accepts connection

3. Alice nods her head, and says 'Hello' to Bob. 
> client sends `ACK` (TCP packet containing an acknowledge flag) followed by `CLIENT_HELLO` message (protocol_version; random_data; session_id; cipher_suites; compression_methods; extensions;)

3.1 Bob has no clue what Alice is saying and he just turns away from her.
> server sends `ALERT`, aka warn or error message to the client with short reasoning of why, ex. protocol mismatch.

4. Bob replies back with 'Hello. Lets agree on English.' to Alice.
> server sends `SERVER_HELLO` message, and creates session.

5. Bob introduces his birth certificate, to ensure Alice, that he is actually Bob for real.
> server sends `CERTIFICATE` message, containing information about the server (its identity, domain name) and its public key.
    5.1 Alice read the certificate and validates it - since we are using self-signed certificate (using servers private_key), there is no Certificate Authority (CA) involved.

6. Bob creates a secret phrase, so can speak to Alice, without anyone understanding (eavesdropping) them.

## Notes

Uses underlaying TCP server to handle buffer streaming, therefore message splitting needs to be handled as well.
There might be some place for further buffer optimization, but the builder pattern used does okay job.
Protocol extensions which the server can use to take action, or enable new features, are omit.
Most likely not all error cases are handled, with sending proper alert signal back to client.
No self recover nor any retry logic in case of failed tls phase, connection is simply terminated.
Server is using self-signed certs (generated via OpenSSL).
Sessions are kept in-memory process.

## Crypto

Resolved cipher suite for the demo is `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`, which stands for:

1. ECDHE - describes the key exchange algorithm, using `Elliptic Curve Deffie-Hellman Ephemeral`, in other words securely negotiate a shared secret between the client and server, separate from the server certs. The picked curve is `x25519`
2. RSA - describes the `certificates` encryption algorithm, used for `signing key exchange` params as well as for `authentication`
3. AES_128_CBC - describes the `symmetric encryption` algorithm, used during `data` transfer, stands for Advanced Encrpytion Standard with 128-bit key length and Cipher Block Chaining mode, when encrypting data
4. SHA - describes the `hashing` algorithm, used for integrity verification