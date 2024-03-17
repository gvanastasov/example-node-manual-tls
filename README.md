# example-node-manual-tls
A dummy example of TLS implementation. Reminder don't use this in production.

## Getting started
```sh
npm run start:server
npm run connect:client
```

> Server and client are using port 3000, if that is not available for you, just pass an arg `cmd -- --port=x`, and of course make sure you start the server and connect the client on that very same port...

## The play (ping-pong):

Phase 1: three-way handshake, which is a process used to establish a connection between two devices on a network.

1. Alice waves to Bob.
> client send `SYN` (TCP packet containing a synchronize flag) to server, aka tries to connect to server

2. Bob waves back to Alice.
> server sends `SYN-ACK` (TCP packet containing the synchronize and acknowledge flags set) to client, aka accepts connection

3. Alice nods her head, and says 'Hello' to Bob. 
> client sends `ACK` (TCP packet containing an acknowledge flag) followed by `CLIENT_HELLO` message (protocol_version; random_data; session_id; cipher_suites; compression_methods; extensions;)

4. Bob replies back with 'Hello' to Alice.
> server sends `SERVER_HELLO` message can follow the requested protocol, or closes connection if not.

## Notes

Protocol extensions which the server can use to take action, or enable new features, are omit.
Most likely not all error cases are handled, with sending proper alert signal back to client.
No self recover nor any retry logic in case of failed tls phase, connection is simply terminated.