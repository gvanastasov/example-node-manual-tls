const net = require('net');
const { ContentType, createRecordHeader } = require('./tls-record-header');
const { HandshakeType, createHandshakeHeader } = require('./tls-handshake-header');
const { TLSVersion, createClientVersion } = require('./tls-version');
const { CipherSuits } = require('./tls-ciphers');
const { createMessage, readMessage } = require('./tls-message');

function connect(address, port) {
  const client = new net.Socket();

  // Step 1: client sends SYN to server
  console.log('[client]: send SYN');
  client.connect(port, address, () => {

    client.on('data', handleDataReceived);

    // Step 2: client receives SYN-ACK to server
    console.log('[client]: received SYN-ACK from server [%s%s]', address, port);
    
    // Step 3: client send ACK & CLIENT_HELLO to server
    console.log('[client]: sends ACK & CLIENT_HELLO to server');
    sendClientHello();

    function handleDataReceived(data) {
      // todo: parse data
    }

    function sendClientHello() {
      let message = createMessage({
        contentType: ContentType.Handshake,
        version: TLSVersion.TLS_1_2
      })
        .handshake({
          handshakeType: HandshakeType.ClientHello
        })
        .version({
          version: TLSVersion.TLS_1_2
        })
        .random()
        // todo: pass existing session id if available
        .sessionId()
        .cipherSuites({
          cs: [
            CipherSuits.TLS_RSA_WITH_AES_128_CBC_SHA
          ]
        })
        .build();

      client.write(message);
    }
  });

  client.on('end', () => {
    console.log('[client]: connection closed');
  });

  client.on('error', err => {
    console.error('[client]: error -', err.message);
  });
}

module.exports = { connect }