const net = require('net');
const { messageBuilder, parseMessage, _k } = require('./message');

function connect(address, port) {
  const client = new net.Socket();

  const config = {
    tlsVersion: _k.ProtocolVersion.TLS_1_2,
    cipherSuites: [
      _k.CipherSuits.TLS_RSA_WITH_AES_128_CBC_SHA,
      _k.CipherSuits.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    ],
    compressionMethods: [
      _k.CompressionMethods.NULL
    ]
  }

  const handles = {
    [_k.ContentType.Handshake]: {
      [_k.HandshakeType.ServerHello]: handleServerHello,
      [_k.HandshakeType.Certificate]: handleCertificate,
      [_k.HandshakeType.ServerKeyExchange]: handleServerKeyExchange,
      [_k.HandshakeType.ServerHelloDone]: handleServerHelloDone,
    },
    [_k.ContentType.Alert]: handleAlert,
  }

  function handleMessage(message) {
      let contentType = message.headers.record.contentType.value;
      switch (message.headers.record.contentType.value) {
        case _k.CONTENT_TYPE.Handshake:
          {
            // todo: handle unknown handshake types
            handles[contentType][annotation](message);
            break;
          }
        case _k.CONTENT_TYPE.Alert:
          {
            console.log(
              '[client]: received %s from server - %s', 
              message.alert.level.name, 
              message.alert.description.name
            );
            break;
          }
        default:
          {
            console.log('[client]: received unknown message type - %s', contentType);
          }
      }
  }

  // Step 1
  console.log('[client]: send SYN');
  client.connect(port, address, () => {
    client.on('data', onConnectionDataReceive);

    // Step 2
    console.log('[client]: received SYN-ACK from server [%s%s]', address, port);
    
    // Step 3
    console.log('[client]: sends ACK & CLIENT_HELLO to server');
    sendClientHello();
  
    function onConnectionDataReceive(data) {
      let message = parseMessage(data);
      handleMessage(message);
    }
  });

  function sendClientHello() {
    let message = messageBuilder()
        .add(_k.Annotations.RECORD_HEADER, { contentType: _k.ContentType.Handshake, version: config.tlsVersion })
        .add(_k.Annotations.HANDSHAKE_HEADER, { type: _k.HandshakeType.ClientHello, length: 0 })
        .add(_k.Annotations.VERSION, { version: config.tlsVersion })
        .add(_k.Annotations.RANDOM)
        // todo: pass existing session id if available
        .add(_k.Annotations.SESSION_ID, { id: '0' })
        .add(_k.Annotations.CIPHER_SUITES, { ciphers: config.cipherSuites })
        .add(_k.Annotations.COMPRESSION_METHODS, { methods: config.compressionMethods })
        .build();

    client.write(message);
  }

  function handleServerHello(message) {
    // Step 4
    console.log('[client]: received SERVER_HELLO from server - [%s%s]', address, port);
  }

  function handleCertificate(message) {
    // Step 5
    console.log('[client]: received CERTIFICATE from server - [%s%s]', address, port);
  }

  function handleServerKeyExchange(message) {
    // Step 6
    console.log('[client]: received SERVER_KEY_EXCHANGE from server - [%s%s]', address, port);
  }

  function handleServerHelloDone(message) {
    // Step 7
    console.log('[client]: received SERVER_HELLO_DONE from server - [%s%s]', address, port);
  }

  function handleAlert(message) {
    console.log(
      '[client]: received %s from server - %s', 
      message.alert.level.name, 
      message.alert.description.name
    );
  }

  client.on('end', () => {
    console.log('[client]: connection closed');
  });

  client.on('error', err => {
    console.error('[client]: error -', err.message);
  });
}

module.exports = { connect }