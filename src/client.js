const net = require('net');
const crypto = require('crypto');

const { resolveHashingFunction, resolveEncryptionAlgorithm } = require('./utils/crypto');
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
      clientRandom: null,
      clientPrivateKey: null,
      clientPublicKey: null,
      clientWriteKey: null,
      digest: {
        value: Buffer.alloc(0),
        in: (message) => {
          const payload = message.subarray(_k.Dimensions.RecordHeader.Bytes);
          this.connection.encryption.digest.value = Buffer.concat([this.connection.encryption.digest.value, payload]);
        }
      },
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

          context.connection.encryption.digest.in(message._raw);
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
    
    sendClientHello(context);
  
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

  function sendClientHello(context) {
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
        .build({ format: 'object' });
    
    // Step 3
    console.log('[client]: sends [%s] bytes - ACK & CLIENT_HELLO - to: [%s]', message.length, serverAddress);
    client.write(message.buffer);

    context.connection.encryption.clientRandom = message.data[_k.Annotations.RANDOM]._raw;
    context.connection.encryption.digest.in(message.buffer);
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
        padding: resolveEncryptionAlgorithm(message.signature.encryptionAlgorithm),
      },
      Buffer.from(message.signature.value, 'utf8')
    );

    const computedHash = crypto
      .createHash(resolveHashingFunction(message.signature.hashingFunction))
      .update(message.publicKey.value)
      .digest('hex');

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
    sendClientKeyExchange(context);
  }

  function sendClientKeyExchange(context) {
    // todo: move type of asymetric encryption and curve to constants instead
    // and it should be part of the cipher suite resolver and not hardcoded here.  
    const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
    const publicExport = publicKey.export({ type: 'spki', format: 'der' });

    context.connection.encryption.clientPrivateKey = privateKey;
    context.connection.encryption.clientPublicKey = publicKey;

    let message = new messageBuilder()
      .add(_k.Annotations.RECORD_HEADER, { contentType: _k.ContentType.Handshake, version: clientConfig.tlsVersion })
      .add(_k.Annotations.HANDSHAKE_HEADER, { type: _k.HandshakeType.ClientKeyExchange })
      .add(_k.Annotations.PUBLIC_KEY, { key: publicExport })
      .build();

    // Step 8
    console.log('[client]: sends [%s] bytes - CLIENT_KEY_EXCHANGE - to: [%s]', message.length, context.connection.serverAddress);
    client.write(message);
    context.connection.encryption.digest.in(message);

    sendClientChangeCipherSpec(context);
  }

  function sendClientChangeCipherSpec(context) {
    const preMasterKey = crypto.diffieHellman({
      privateKey: context.connection.encryption.clientPrivateKey,
      publicKey: crypto.createPublicKey(
        {
          key: context.connection.encryption.serverPublicKey,
          format: 'der',
          type: 'spki',
        }),
    });

    const seed = Buffer.concat([
      Buffer.from('master secret'), 
      context.connection.encryption.clientRandom, 
      context.connection.encryption.serverRandom._raw
    ]);

    const a0 = seed;
    const a1 = crypto.createHmac('sha256', preMasterKey).update(a0).digest();
    const a2 = crypto.createHmac('sha256', preMasterKey).update(a1).digest();

    const p1 = crypto.createHmac('sha256', preMasterKey).update(Buffer.concat([a1, seed])).digest();
    const p2 = crypto.createHmac('sha256', preMasterKey).update(Buffer.concat([a2, seed])).digest();

    context.connection.encryption.masterSecret = Buffer.concat([p1.subarray(0, 32), p2.subarray(0, 16)]);

    const seedKE = Buffer.concat([
        Buffer.from('key expansion'),
        context.connection.encryption.clientRandom, 
        context.connection.encryption.serverRandom._raw
    ]);

    const pValues = [];
    let a = seedKE;
    while (pValues.length < 4) {
        a = crypto.createHmac('sha256', context.connection.encryption.masterSecret).update(a).digest();
        pValues.push(crypto.createHmac('sha256', context.connection.encryption.masterSecret).update(Buffer.concat([a, seedKE])).digest());
    }

    // Concatenate all the p values to obtain a single buffer p
    const p = Buffer.concat(pValues);

    context.connection.encryption.client_write_mac_key = p.subarray(0, 20);
    context.connection.encryption.server_write_mac_key = p.subarray(20, 40);
    context.connection.encryption.client_write_key = p.subarray(40, 56);
    context.connection.encryption.server_write_key = p.subarray(56, 72);
    context.connection.encryption.client_write_iv = p.subarray(72, 88);
    context.connection.encryption.server_write_iv = p.subarray(88, 104);

    let message = new messageBuilder()
      .add(_k.Annotations.RECORD_HEADER, { contentType: _k.ContentType.ChangeCipherSpec, version: clientConfig.tlsVersion })
      .build();

    // Step 9
    console.log('[client]: sends [%s] bytes - CHANGE_CIPHER_SPEC - to: [%s]', message.length, context.connection.serverAddress);
    client.write(message);
    context.connection.encryption.digest.in(message);

    sendClientHandshakeFinished(context);
  }

  function sendClientHandshakeFinished(context) {
    const handshakeDigest = context.connection.encryption.digest.value;
    // todo: we should inffer this from the cipher suite instead of hardcoded
    const handshakeDigestHash = crypto.createHash('sha256').update(handshakeDigest).digest();
    const seed = Buffer.concat([Buffer.from('client finished'), handshakeDigestHash]);
    let a0 = seed; 
    // todo: we should inffer this from the cipher suite instead of hardcoded
    const a1 = crypto.createHmac('sha256', context.connection.encryption.masterSecret).update(a0).digest();
    const p1 = crypto.createHmac('sha256', context.connection.encryption.masterSecret).update(Buffer.concat([a1, seed])).digest();
    const verifyData = p1.subarray(0, 12);

    // todo: we should inffer this from the cipher suite instead of hardcoded
    let iv = crypto.randomBytes(16);

    let encryptedMessageInput = Buffer.concat([
      new messageBuilder()
        .add(_k.Annotations.HANDSHAKE_HEADER, { type: _k.HandshakeType.Finished, length: 12 })
        .build(),
      verifyData
    ]);

    // todo: we should inffer this from the cipher suite instead of hardcoded
    const cipher = crypto
      .createCipheriv('aes-128-cbc', context.connection.encryption.client_write_key, iv);

    let encryptedMessage = cipher.update(encryptedMessageInput);
    encryptedMessage = Buffer.concat([encryptedMessage, cipher.final()]);

    // Encrypt the message
    // const cipher = crypto.createCipheriv('aes-128-cbc', context.connection.encryption.client_write_key, iv);
    // let encryptedMessage = cipher.update(encryptedMessageInput);
    // encryptedMessage = Buffer.concat([encryptedMessage, cipher.final()]);

    // // Decrypt the message
    // const decipher = crypto.createDecipheriv('aes-128-cbc', context.connection.encryption.client_write_key, iv);
    // let decryptedMessage = decipher.update(encryptedMessage);
    // decryptedMessage = Buffer.concat([decryptedMessage, decipher.final()]);

    let message = new messageBuilder()
      .add(_k.Annotations.RECORD_HEADER, { contentType: _k.ContentType.Handshake, version: clientConfig.tlsVersion })
      // todo: we should inffer this from the cipher suite instead of hardcoded
      .add(_k.Annotations.ENCRYPTION_IV, { vector: iv })
      .add(_k.Annotations.ENCRYPTED_DATA, { data: encryptedMessage })
      .build();

    // Step 10
    console.log('[client]: sends [%s] bytes - CLIENT_HANDSHAKE_FINISHED - to: [%s]', message.length, context.connection.serverAddress);
    client.write(message);
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