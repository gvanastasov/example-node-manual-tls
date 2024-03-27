const net = require('net');
const os = require('os');
const crypto = require('crypto');

const { generateRandomBytes } = require('./utils/hex');
const { resolveHashingFunction, resolveEncryptionAlgorithm } = require('./utils/crypto');
const { messageBuilder, parseMessage, _k  } = require('./message');

// move out of here
function session() {
    function generateId() {
        const bytes = generateRandomBytes(8);
        const timestamp = Date.now();
        for (let i = 0; i < 8; i++) {
            bytes.push((timestamp >> (i * 8)) & 0xFF);
        }
        return bytes;
    }
    
    this.id = generateId();
    this.clientRandom = null;
    this.clientPublicKey = null;
    this.clientEncrypted = false;
    this.serverRandom = null;
    this.privateKey = null;
    this.publicKey = null;
    this.digest = {
        value: Buffer.alloc(0),
        in: (message) => {
          const payload = message.subarray(_k.Dimensions.RecordHeader.Bytes);
          this.digest.value = Buffer.concat([this.digest.value, payload]);
        },
      };

    return this;
}

function createServer({ hostname = 'localhost', key, csr, cert } = {}) {
    const server = net.createServer();
    const sessions = [];

    server.on('connection', handleConnection);
    
    console.log('[server]: created...')

    const serverConfig = {
        version: _k.ProtocolVersion.TLS_1_2,
        cipherSuites: [
            _k.CipherSuits.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        ],
        key,
        cert,
        csr
    }

    const handles = {
        [_k.ContentType.Handshake]: {
            [_k.HandshakeType.ClientHello]: handleClientHello,
            [_k.HandshakeType.ClientKeyExchange]: handleClientKeyExchange,
            [_k.HandshakeType.ClientHandshakeFinished]: handleClientHandshakeFinished,
        },
        [_k.ContentType.ChangeCipherSpec]: handleClientChangeCipherSpec,
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
            case _k.ContentType.ChangeCipherSpec:
            {
                handles[contentType](context);
                break;
            }
            default: 
            {
                console.error('Not implemented yet...');
                break;
            }
        }
    }

    function handleConnection(socket) {
        const remoteAddress = socket.remoteAddress + ':' + socket.remotePort; 
        
        // todo: move to class/func
        let context = { 
            message: null,
            session: null,
            socket, 
            remoteAddress
        };

        let buffer = Buffer.alloc(0);

        // Step 1 (handled by TCP server)
        console.log('[server]: received - SYN - from: [%s]', remoteAddress);
    
        // Step 2 (handled by TCP server)
        console.log('[server]: send - SYN-ACK - to: [%s]', remoteAddress);

        socket.on('data', onConnectionDataReceive); 
        socket.on('error', onConnectionError);
        socket.once('close', onConnectionClose);

        function onConnectionDataReceive (data) {
            buffer = Buffer.concat([buffer, data]);

            while(buffer.length >= _k.Dimensions.RecordHeader.Bytes) {            
                let messageLength = buffer.readUInt16BE(_k.Dimensions.RecordHeader.Length.Start);
    
                if (buffer.length >= messageLength + _k.Dimensions.RecordHeader.Bytes) {
                    let messageData = Uint8Array.prototype.slice.call(buffer, 0, messageLength + _k.Dimensions.RecordHeader.Bytes);
                    buffer = buffer.subarray(messageLength + _k.Dimensions.RecordHeader.Bytes);
                    
                    context.message = parseMessage(
                        messageData, 
                        context.session?.clientEncrypted, decrypt);
                    handleMessage(context);
                }
            }
        };

        function decrypt({ iv, data }) {
            const decipher = crypto.createDecipheriv('aes-128-cbc', context.session.client_write_key, iv);
            let decrypted = decipher.update(data);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            return decrypted;
        }

        function onConnectionError(err) {
            console.log('[%s] connection error: %s', remoteAddress, err.message);  
        }

        function onConnectionClose() {  
            console.log('[%s] connection closed.', remoteAddress);  
        }
    };

    function handleClientHello(context) {
        // Step 3
        console.log('[server]: received [%s] bytes - ACK & CLIENT_HELLO - from: [%s]', context.message._raw.length, context.remoteAddress);

        // Step 3.1: server protocol version not supported
        if (context.message[_k.Annotations.VERSION] !== serverConfig.version) {
            console.log('[server]: protocol version not supported - [%s]', context.remoteAddress);
            return alert(context, {
                level: _k.AlertLevel.FATAL, 
                description: _k.AlertDescription.PROTOCOL_VERSION
            });
        }

        // Step 3.2
        // todo: check session
        context.session = new session();
        context.session.clientRandom = context.message[_k.Annotations.RANDOM]._raw;
        context.session.digest.in(context.message._raw);

        // todo: improve session management
        sessions.push(context.session);
        
        sendServerHello(context);
    }

    function sendServerHello(context) {
        let requestCipherSuites = context.message[_k.Annotations.CIPHER_SUITES].map(x => x.value);
        let negotiatedCipher = negotiateCipherSuite(requestCipherSuites, serverConfig.cipherSuites);

        // Step 4.1: unable to negotiate cipher suite
        if (negotiatedCipher === null) {
            console.log('[server]: unable to negotiate cipher suite - [%s]', context.remoteAddress);
            return alert({ 
                level: _k.AlertLevel.FATAL, 
                description: _k.AlertDescription.HANDSHAKE_FAILURE
            });
        }

        let message = messageBuilder()
            .add(_k.Annotations.RECORD_HEADER, { contentType: _k.ContentType.Handshake, version: serverConfig.version })
            .add(_k.Annotations.HANDSHAKE_HEADER, { type: _k.HandshakeType.ServerHello, length: 0 })
            .add(_k.Annotations.VERSION, { version: serverConfig.version })
            .add(_k.Annotations.RANDOM)
            .add(_k.Annotations.SESSION_ID, { id: context.session.id })
            .add(_k.Annotations.CIPHER_SUITES, { ciphers: [negotiatedCipher] })
            .add(_k.Annotations.COMPRESSION_METHODS, { methods: [_k.CompressionMethods.NULL] })
            .build({ format: 'object' });

        // Step 4: server sends SERVER_HELLO
        console.log('[server]: send [%s] bytes - SERVER_HELLO - to: [%s]', message.buffer.length, context.remoteAddress);
        context.socket.write(message.buffer);
        context.session.serverRandom = message.data[_k.Annotations.RANDOM]._raw;
        context.session.digest.in(message.buffer);

        sendCertificate(context);
    }

    function sendCertificate(context) {
        let message = messageBuilder()
            .add(_k.Annotations.RECORD_HEADER, { contentType: _k.ContentType.Handshake, version: serverConfig.version })
            .add(_k.Annotations.HANDSHAKE_HEADER, { type: _k.HandshakeType.Certificate, length: 0 })
            .add(_k.Annotations.CERTIFICATE, { cert: serverConfig.cert })
            .build();

        // Step 5
        console.log('[server]: send [%s] bytes - CERTIFICATE - to: [%s]', message.length, context.remoteAddress);
        context.socket.write(message);
        context.session.digest.in(message);

        sendServerKeyExchange(context);
    }

    function sendServerKeyExchange(context) {
        const passphrase = process.env.SERVER_PCERT_PASSPHRASE;
        if (!passphrase) {
            return alert({ 
                level: _k.AlertLevel.FATAL, 
                description: _k.AlertDescription.INTERNAL_ERROR
            });
        }

        // todo: move type of asymetric encryption and curve to constants instead
        // and it should be part of the cipher suite resolver and not hardcoded here.  
        const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
        const publicExport = publicKey.export({ type: 'spki', format: 'der' });

        context.session.privateKey = privateKey;
        context.session.publicKey = publicKey;

        const hash = crypto
            .createHash(resolveHashingFunction(_k.HashingFunctions.SHA256))
            .update(publicExport)
            .digest();

        const signature = crypto.privateEncrypt(
            {
                key: serverConfig.key,
                passphrase,
                padding: resolveEncryptionAlgorithm(_k.EncryptionAlgorithms.RSA)
            },
            Buffer.from(hash, 'utf8')
        );

        const message = messageBuilder()
            .add(_k.Annotations.RECORD_HEADER, { contentType: _k.ContentType.Handshake, version: serverConfig.version })
            .add(_k.Annotations.HANDSHAKE_HEADER, { type: _k.HandshakeType.ServerKeyExchange, length: 0 })
            .add(_k.Annotations.CURVE_INFO, { curve: _k.EllipticCurves.x25519 })
            .add(_k.Annotations.PUBLIC_KEY, { key: publicExport })
            .add(_k.Annotations.SIGNATURE, { 
                signature,
                encryptionAlgorithm: _k.EncryptionAlgorithms.RSA, 
                hashingFunction: _k.HashingFunctions.SHA256
            })
            .build();

        // Step 6: server sends SERVER_KEY_EXCHANGE
        console.log('[server]: send [%s] bytes - SERVER_KEY_EXCHANGE - to: [%s]', message.length, context.remoteAddress);
        context.socket.write(message);
        context.session.digest.in(message);

        sendServerHelloDone(context);
    }

    function sendServerHelloDone(context) {
        let message = messageBuilder()
            .add(_k.Annotations.RECORD_HEADER, { contentType: _k.ContentType.Handshake, version: serverConfig.version })
            .add(_k.Annotations.HANDSHAKE_HEADER, { type: _k.HandshakeType.DoneHello, length: 0 })
            .build();

        // Step 7: server sends SERVER_HELLO_DONE
        console.log('[server]: send [%s] bytes - SERVER_HELLO_DONE - to: [%s]', message.length, context.remoteAddress);
        context.socket.write(message);
        context.session.digest.in(message);
    }

    function handleClientKeyExchange(context) {
        // Step 8
        console.log('[server]: received [%s] bytes - CLIENT_KEY_EXCHANGE - from: [%s]', context.message._raw.length, context.remoteAddress);
        context.session.clientPublicKey = context.message[_k.Annotations.PUBLIC_KEY].value;
        context.session.digest.in(context.message._raw);
    }

    function handleClientChangeCipherSpec(context) {
        // Step 9
        console.log('[server]: received - CHANGE_CIPHER_SPEC - from: [%s]', context.remoteAddress);
        context.session.clientEncrypted = true;

        const preMasterKey = crypto.diffieHellman({
            privateKey: context.session.privateKey,
            publicKey: crypto.createPublicKey({
                key: context.session.clientPublicKey,
                format: 'der',
                type: 'spki'
            })
        });

        const seed = Buffer.concat([
            Buffer.from('master secret'), 
            context.session.clientRandom,
            context.session.serverRandom
          ]);

          const a0 = seed;
          const a1 = crypto.createHmac('sha256', preMasterKey).update(a0).digest();
          const a2 = crypto.createHmac('sha256', preMasterKey).update(a1).digest();
      
          const p1 = crypto.createHmac('sha256', preMasterKey).update(Buffer.concat([a1, seed])).digest();
          const p2 = crypto.createHmac('sha256', preMasterKey).update(Buffer.concat([a2, seed])).digest();
      
          context.session.masterSecret = Buffer.concat([p1.subarray(0, 32), p2.subarray(0, 16)]);
      
          const seedKE = Buffer.concat([
              Buffer.from('key expansion'),
              context.session.clientRandom,
              context.session.serverRandom
          ]);
      
          const pValues = [];
          let a = seedKE;
          while (pValues.length < 4) {
              a = crypto.createHmac('sha256', context.session.masterSecret).update(a).digest();
              pValues.push(crypto.createHmac('sha256', context.session.masterSecret).update(Buffer.concat([a, seedKE])).digest());
          }
      
          // Concatenate all the p values to obtain a single buffer p
          const p = Buffer.concat(pValues);
      
          context.session.client_write_mac_key = p.subarray(0, 20);
          context.session.server_write_mac_key = p.subarray(20, 40);
          context.session.client_write_key = p.subarray(40, 56);
          context.session.server_write_key = p.subarray(56, 72);
          context.session.client_write_iv = p.subarray(72, 88);
          context.session.server_write_iv = p.subarray(88, 104);
    }

    function handleClientHandshakeFinished(context) {
        // todo: compute digest and verify data
        const handshakeDigest = context.session.digest.value;
        // todo: we should inffer this from the cipher suite instead of hardcoded
        const handshakeDigestHash = crypto.createHash('sha256').update(handshakeDigest).digest();
        const seed = Buffer.concat([Buffer.from('client finished'), handshakeDigestHash]);
        let a0 = seed; 
        // todo: we should inffer this from the cipher suite instead of hardcoded
        const a1 = crypto.createHmac('sha256', context.session.masterSecret).update(a0).digest();
        const p1 = crypto.createHmac('sha256', context.session.masterSecret).update(Buffer.concat([a1, seed])).digest();
        const verifyData = p1.subarray(0, 12);
        console.log('[client]: verify data - %s', verifyData.toString('hex'));

        if (verifyData.toString('hex') !== context.message[_k.Annotations.VERIFY_DATA].toString('hex')) {
            console.log('[server]: verify data mismatch - [%s]', context.remoteAddress);
            return alert(context, {
                level: _k.AlertLevel.FATAL, 
                description: _k.AlertDescription.HANDSHAKE_FAILURE
            });
        }

        // Step 10
        console.log('[server]: received - CLIENT_HANDSHAKE_FINISHED - from: [%s]', context.remoteAddress);
    }

    function alert(context, { level, description }) {
        const message = messageBuilder()
            .add(_k.Annotations.RECORD_HEADER, { contentType: _k.ContentType.Alert, version: serverConfig.version })
            .add(_k.Annotations.ALERT, { level, description })
            .build();
        context.socket.write(message);
        context.socket.end();
    }

    // todo: move to utils and rename to find first common or w/e
    function negotiateCipherSuite(clientSuites, serverSuites) {
        for (let s of serverSuites) {
            for (let c of clientSuites) {
                if (s.value === c.value) {
                    return s;
                }
            }
        }
        return null;
    }

    const address = () => {
        let address = server.address();
        return {
            ...address,
            toString: () => `${address.address}:${address.port}`
        }
    }

    const defaultListeningCallback = (port) => {
        console.log(`[server]: listening on ${hostname}:${port}${os.EOL}`);
    }

    return {
        listen: (port, callback) => server.listen(port, hostname, callback ?? defaultListeningCallback(port)),
        address,
    }
}
  
module.exports = { createServer }