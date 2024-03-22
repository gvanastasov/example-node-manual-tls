const net = require('net');
const { messageBuilder, parseMessage, _k } = require('./message');

function connect(address, port) {
  const client = new net.Socket();

  const clientConfig = {
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
      [_k.HandshakeType.DoneHello]: handleServerHelloDone,
    },
  }

  function handleMessage(context) {
    let { contentType } = context.message[_k.Annotations.RECORD_HEADER];
    switch (contentType) {
      case _k.ContentType.Handshake:
        {
          let { type: handshakeType } = context.message[_k.Annotations.HANDSHAKE_HEADER];
          // todo: handle unknown handshake types
          handles[contentType][handshakeType](context);
          break;
        }
      case _k.ContentType.Alert:
        {
          handleAlert(context.message);
          break;
        }
      default:
        {
          console.log('[client]: received unknown message type - %s', contentType);
          break;
        }
      }
  }

  let buffer = Buffer.alloc(0);
  var serverAddress = address + ':' + port;

  // Step 1
  console.log('[client]: send - SYN - to: [%s]', serverAddress);

  client.connect(port, address, () => {
    client.on('data', onConnectionDataReceive);

    // Step 2
    console.log('[client]: received - SYN-ACK - from [%s]', serverAddress);
    
    sendClientHello({ serverAddress });
  
    /**
     * @description handles byte stream received from the server.
     * Ensures that we process each complete TLS record received over the TCP 
     * connection before attempting to parse and handle it.
     * 
     * @param {Buffer} data 
     */
    function onConnectionDataReceive(data) {
      buffer = Buffer.concat([buffer, data]);

      while(buffer.length >= _k.Dimensions.RecordHeader.Bytes) {
        let messageLength = buffer.readUInt16BE(_k.Dimensions.RecordHeader.Length.Start);
  
        if (buffer.length >= messageLength + _k.Dimensions.RecordHeader.Bytes) {
          let messageData = Uint8Array.prototype.slice.call(buffer, 0, messageLength + _k.Dimensions.RecordHeader.Bytes);
          buffer = buffer.subarray(messageLength + _k.Dimensions.RecordHeader.Bytes);
    
          let message = parseMessage(messageData);
          let context = { message, serverAddress };
          handleMessage(context);
        }
      }
    }
  });

  function sendClientHello({ serverAddress }) {
    let message = messageBuilder()
        .add(_k.Annotations.RECORD_HEADER, { contentType: _k.ContentType.Handshake, version: clientConfig.tlsVersion })
        .add(_k.Annotations.HANDSHAKE_HEADER, { type: _k.HandshakeType.ClientHello, length: 0 })
        .add(_k.Annotations.VERSION, { version: clientConfig.tlsVersion })
        .add(_k.Annotations.RANDOM)
        // todo: pass existing session id if available
        .add(_k.Annotations.SESSION_ID, { id: '0' })
        .add(_k.Annotations.CIPHER_SUITES, { ciphers: clientConfig.cipherSuites })
        .add(_k.Annotations.COMPRESSION_METHODS, { methods: clientConfig.compressionMethods })
        .build();

    // Step 3
    console.log('[client]: sends [%s] bytes - ACK & CLIENT_HELLO - to: [%s]', message.length, serverAddress);
    client.write(message);
  }

  function handleServerHello(context) {
    // Step 4
    console.log('[client]: received [%s] bytes - SERVER_HELLO - from: [%s]', context.message._raw.length, context.serverAddress);
  }

  function handleCertificate(context) {
    // Step 5
    console.log('[client]: received [%s] bytes - CERTIFICATE - from: [%s]', context.message._raw.length, context.serverAddress);
  }

  function handleServerKeyExchange(context) {
    // Step 6
    console.log('[client]: received [%s] bytes - SERVER_KEY_EXCHANGE - from: [%s]', context.message._raw.length, context.serverAddress);
  }

  function handleServerHelloDone(context) {
    // Step 7
    console.log('[client]: received [%s] bytes - SERVER_HELLO_DONE - from: [%s]', context.message._raw.length, context.serverAddress);
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