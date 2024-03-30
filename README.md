# Example NODE TLS
A dummy example of TLS implementation. Check bellow instructions on how to get started, whats included, whats the story play (with Bob and Alice), find references in code and in general get familiar with how TLS 1.2 works. 

`Reminder don't use this in production!`

The intention of this is merely to play around with the protocol implementation detail and learn a thing or two about how most of modern browsing connections are made safer.

## Notes
- Code is written in top-down fashion, so one can actually 'tran'script, or scroll, read through it.
- Uses underlaying TCP server to handle network interfaces and buffer streaming, therefore message splitting needs to be handled as well.
- There might be some place for further buffer optimization, but the builder pattern used does okay job.
- Protocol extensions which the server can use to take action, or enable new features, are omit.
- Likely not all error cases are handled, with sending proper alert signal back to client.
- No self recovery nor any retry logic in case of failed TLS handshake phase, connection is simply terminated.
- In demo, the server is using self-signed certs (generated via OpenSSL) and acting as Certificate Authority.
- Sessions are kept in-memory process.
- There might be todos, notes, some dirty code around - its a demo after all.
- Execution order matters, all operations are synchronous.
- Some of the code inside server and client is intentionally duplicated. In real world those two might be developed by separate parties and not part of a mono repo (like this demo...). Only protocol related code is shared, for example message parsing or simple native utils.
- Yes, TS. Maybe should have, maybe not - the intent was to keep things simple (knowing they are not...)

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

## The story play (ping-pong):

**Chapter 1: The Greet** - Alice sees Bob and wants to talk to him.

```
a connection between two devices on a network starts with three-way handshake.
```

1. [Alice waves to Bob.](./src/client.js:97)

```
client send `SYN` (TCP packet containing a synchronize flag) to server, aka tries to connect to server
```

2. [Bob waves back to Alice.](./src/server.js:102)

```
server sends `SYN-ACK` (TCP packet containing the synchronize and acknowledge flags set) to client, aka accepts connection
```

3. [Alice nods her head, and says 'Hello' to Bob.](./src/client.js:156) 

```
client sends `ACK` (TCP packet containing an acknowledge flag) followed by `CLIENT_HELLO` message (protocol_version; random_data; session_id; cipher_suites; compression_methods; extensions;)
```

- 3.1 [Bob has no clue what Alice is saying and he just turns away from her.](./src/server.js:150)

```
server sends `ALERT`, aka warn or error message to the client with short reasoning of why, ex. protocol mismatch.
```

**Chapter 2: The Handshake** - Bob is a bit of a conspiracy guy and he likes to makes sure no bad guy, who might be listening to his conversations, can understand what he is talking about. For this to happen, Bob needs to ensure whomever he speaks to, has unique way of doing so.

4. [Bob replies back with 'Hello. Lets agree to speak SecretEnglish.' to Alice.](./src/server.js:193)

```
server creates a session and sends `SERVER_HELLO` message, which would include agreement on communication version, cipher suite to use for crypting the connection and some other things.
```

5. [Bob introduces his birth certificate, to ensure Alice, that he is actually Bob for real.](./src/server.js:209)

```
server sends `CERTIFICATE` message, containing information about the server (its identity, domain name) and its public key.
``` 

- 5.1 [Alice read Bob's birth certificate and validates it.](./src/client.js:175)

```
since we are using self-signed certificate (using servers private_key), the Certificate Authority (CA) involved is the server itself, hence not much validation to do there (aka decrypt and validate against it, for authentication reasons) - we simply trust it.
```

6. [Bob thinks of two magical numbers 1 and 9, and share one of them with Alice.](./src/server.js:260)

```
server generates a set of asymmetric keys, and then shares the public one via  `SERVER_KEY_EXCHANGE` message send to the client. Reminder, that the keys generated on the server are per session, due to the cipher suite chosen.
```

7. [Bob asks Alice to do the same.](./src/server.js:274)

8. [Alice thinks of two magical numbers 3 and 7, and shares one of them with Bob.](./src/client.js:236)

```
client also generates a set of asymmetric keys, and then shares the public one via `CLIENT_KEY_EXCHANGE` message send to the server.
```

9. [Alice creates a Secret from Bob's public number and her private one.](./src/client.js:296)

10. [Alica is now ready to speak SecretEnglish with Bob.](./src/client.js:321)

11. [Bob creates a Secret from Alice's public number and his private one.](./src/server.js:323)

12. [Bob is now ready to speak SecretEnglish with Alice](./src/server.js:345)

13. [Alice says 'Ping'](./src/client.js:361)

14. [Bob replies with 'Pong'](./src/server.js:356)

**Chapter 3: The Secret Dialog**

## Cipher Suite

Resolved cipher suite for the demo is `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`, which stands for:

1. ECDHE - describes the key exchange algorithm, using `Elliptic Curve Deffie-Hellman Ephemeral`, in other words securely negotiate a shared secret between the client and server, separate from the server certs. The picked curve is `x25519`
2. RSA - describes the `certificates` encryption algorithm, used for `signing key exchange` params as well as for `authentication`
3. AES_128_CBC - describes the `symmetric encryption` algorithm, used during `data` transfer, stands for Advanced Encrpytion Standard with 128-bit key length and Cipher Block Chaining mode, when encrypting data
4. SHA - describes the `hashing` algorithm, used for integrity verification

## Contribution

Are you missing something, or you found a nonce'nse - PRs are welcome.