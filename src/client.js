const net = require('net');
const { createMessage, parseMessage, _k } = require('./tls');

function connect(address, port) {
  const client = new net.Socket();

  const config = {
    tlsVersion: _k.PROTOCOL_VERSION.TLS_1_2,
    cipherSuites: [
      _k.CIPHER_SUITES.TLS_RSA_WITH_AES_128_CBC_SHA
    ],
    compressionMethods: [
      _k.COMPRESSION_METHODS.NULL
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
      let message = parseMessage(data);

      switch (message.headers.record.contentType.value) {
        case _k.CONTENT_TYPE.Alert:
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
        contentType: _k.CONTENT_TYPE.Handshake,
        version: config.tlsVersion
      })
        .append(_k.BUFFERS.HANDSHAKE_HEADER, { type: _k.HANDSHAKE_TYPE.ClientHello, length: 0 })
        .append(_k.BUFFERS.VERSION, { version: config.tlsVersion })
        .append(_k.BUFFERS.RANDOM)
        // todo: pass existing session id if available
        .append(_k.BUFFERS.SESSION_ID)
        .append(_k.BUFFERS.CIPHERS, { ciphers: config.cipherSuites })
        .append(_k.BUFFERS.COMPRESSION, { methods: config.compressionMethods });

      client.write(message.buffer);
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