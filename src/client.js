const net = require('net');
const { ContentType } = require('./tls-record-header');
const { HandshakeType } = require('./tls-handshake-header');
const { TLSVersion } = require('./tls-version');
const { CipherSuits } = require('./tls-ciphers');
const { CompressionMethods } = require('./tls-compression');
const { createMessage, parseMessage } = require('./tls-message');

function connect(address, port) {
  const client = new net.Socket();

  const config = {
    tlsVersion: TLSVersion.TLS_1_2,
    cipherSuites: [
      CipherSuits.TLS_RSA_WITH_AES_128_CBC_SHA
    ],
    compressionMethods: [
      CompressionMethods.NULL
    ]
  }

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
      let message = parseMessage(data);

      switch (message.headers.record.contentType.value) {
        case ContentType.Alert:
          {
            console.log(
              '[client]: received %s from server - %s', 
              message.alert.level.name, 
              message.alert.description.name
            );
            break;
          }
      }
    }

    function sendClientHello() {
      let message = createMessage({
        contentType: ContentType.Handshake,
        version: config.tlsVersion
      })
        .handshake({
          handshakeType: HandshakeType.ClientHello
        })
        .version({
          version: config.tlsVersion
        })
        .random()
        // todo: pass existing session id if available
        .sessionId()
        .cipherSuites({
          cs: config.cipherSuites
        })
        .compressionMethods({
          methods: config.compressionMethods
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