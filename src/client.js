const net = require('net');
const crypto = require('crypto');

const { messageBuilder, parseMessage, _k } = require('./message');

function clientContext({ serverAddress }) {
  this.connection = {
    serverAddress,
    buffer: Buffer.alloc(0),
    encryption: {
      cipherSuite: null,
      masterSecret: null,
      version: null,
      serverRandom: null,
      serverPublicCert: null,
      serverPublicKey: null,
    },
    session: {
      id: null,
    },
  }

  return this;
}

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

  function handleMessage(message, context) {
    let { contentType } = message[_k.Annotations.RECORD_HEADER];
    switch (contentType) {
      case _k.ContentType.Handshake:
        {
          let { type: handshakeType } = message[_k.Annotations.HANDSHAKE_HEADER];
          // todo: handle unknown handshake types
          handles[contentType][handshakeType](message, context);
          break;
        }
      case _k.ContentType.Alert:
        {
          handleAlert(message);
          break;
        }
      default:
        {
          console.log('[client]: received unknown message type - %s', contentType);
          break;
        }
      }
  }

  // Step 1
  let serverAddress = `${address}:${port}`;
  console.log('[client]: send - SYN - to: [%s]', serverAddress);

  client.connect(port, address, () => {
    const context = new clientContext({ serverAddress });

    client.on('data', (data) => onConnectionDataReceive(data, context));

    // Step 2
    console.log('[client]: received - SYN-ACK - from [%s]', context.connection.serverAddress);
    
    sendClientHello();
  
    /**
     * @description handles byte stream received from the server.
     * Ensures that we process each complete TLS record received over the TCP 
     * connection before attempting to parse and handle it.
     * 
     * @param {Buffer} data 
     */
    function onConnectionDataReceive(data, context) {
      let { buffer } = context.connection;

      buffer = Buffer.concat([buffer, data]);

      while(buffer.length >= _k.Dimensions.RecordHeader.Bytes) {
        let messageLength = buffer.readUInt16BE(_k.Dimensions.RecordHeader.Length.Start);
  
        if (buffer.length >= messageLength + _k.Dimensions.RecordHeader.Bytes) {
          let messageData = Uint8Array.prototype.slice.call(buffer, 0, messageLength + _k.Dimensions.RecordHeader.Bytes);
          buffer = buffer.subarray(messageLength + _k.Dimensions.RecordHeader.Bytes);
    
          const message = parseMessage(messageData);
          handleMessage(message, context);
        }
      }
    }
  });

  function sendClientHello() {
    let message = new messageBuilder()
        .add(_k.Annotations.RECORD_HEADER, { contentType: _k.ContentType.Handshake, version: clientConfig.tlsVersion })
        .add(_k.Annotations.HANDSHAKE_HEADER, { type: _k.HandshakeType.ClientHello, length: 0 })
        .add(_k.Annotations.VERSION, { version: clientConfig.tlsVersion })
        // todo: store random on the session context
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

  function handleServerHello(message, context) {
    context.connection.encryption.cipherSuite = message[_k.Annotations.CIPHER_SUITES][0].value;
    context.connection.encryption.version = message[_k.Annotations.VERSION];
    context.connection.encryption.serverRandom = message[_k.Annotations.RANDOM];
    context.connection.session.id = message[_k.Annotations.SESSION_ID].sessionID;

    // Step 4
    console.log('[client]: received [%s] bytes - SERVER_HELLO - from: [%s]', message._raw.length, context.connection.serverAddress);
  }

  function handleCertificate(message, context) {
    context.connection.encryption.serverPublicCert = message[_k.Annotations.CERTIFICATE].cert;

    // Step 5
    console.log('[client]: received [%s] bytes - CERTIFICATE - from: [%s]', message._raw.length, context.connection.serverAddress);
  }

  function handleServerKeyExchange(message, context) {
    // Step 6
    console.log('[client]: received [%s] bytes - SERVER_KEY_EXCHANGE - from: [%s]', message._raw.length, context.connection.serverAddress);

    const decryptedSignature = crypto.publicDecrypt(
      {
        key: context.connection.encryption.serverPublicCert,
        padding: (() => {
          switch (message.signature.encryptionAlgorithm) {
              case _k.EncryptionAlgorithms.RSA:
                  return crypto.constants.RSA_PKCS1_PADDING;
              default:
                  throw new Error('Unsupported encryption algorithm');
          }
        })(),
      },
      Buffer.from(message.signature.value, 'utf8'));

    const computedHash = crypto.createHash((() => {
      switch (message.signature.hashingFunction) {
          case _k.HashingFunctions.SHA256:
              return 'sha256';
          default:
              throw new Error('Unsupported hashing function');
      }
    })()).update(message.publicKey.value).digest('hex');

    const isAuthenticated = decryptedSignature.toString('hex') === computedHash;
    if (!isAuthenticated) {
      console.error('[client]: server key exchange failed - invalid signature');
      client.end();
    }

    context.connection.encryption.serverPublicKey = message.publicKey.value;
  }

  function handleServerHelloDone(message, context) {
    // Step 7
    console.log('[client]: received [%s] bytes - SERVER_HELLO_DONE - from: [%s]', message._raw.length, context.connection.serverAddress);
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