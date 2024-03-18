const net = require('net');
const os = require('os');
const { createMessage, parseMessage, _k } = require('./tls');
const { generateRandomBytes } = require('./utils');

const sessions = [];

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
    this.serverRandom = null;

    return this;
}

function createServer({ hostname = 'localhost', key, csr, cert } = {}) {
    const config = {
        version: _k.PROTOCOL_VERSION.TLS_1_2,
        cipherSuites: [
            _k.CIPHER_SUITES.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        ],
        key,
        cert,
        csr
    }

    const server = net.createServer();
    server.on('connection', handleConnection);
    
    console.log('[server]: created...')

    function handleConnection(socket) {
        var remoteAddress = socket.remoteAddress + ':' + socket.remotePort; 

        // Step 1: server receives SYN from the client (handled by the tcp server)
        console.log('[server]: received SYN from client - [%s]', remoteAddress);
    
        // Step 2: server send SYN-ACK (handled by the tcp server)
        console.log('[server]: send SYN-ACK to client - [%s]', remoteAddress);

        socket.on('data', onConnectionDataReceive); 
        socket.on('error', onConnectionError);
        socket.once('close', onConnectionClose);

        function onConnectionDataReceive (data) {
            let message = parseMessage(data);
            handleMessage(message);
        };

        function onConnectionError(err) {
            console.log('[%s] connection error: %s', remoteAddress, err.message);  
        }

        function onConnectionClose() {  
            console.log('[%s] connection closed.', remoteAddress);  
        }

        function handleMessage(message) {
            switch (message.headers.record.contentType.value) {
                case _k.CONTENT_TYPE.Handshake:
                {
                    handleHandshake(message);
                    break;
                }
                default: 
                {
                    console.error('Not implemented yet...');
                    break;
                }
            }
        }

        function handleHandshake(message) {
            switch (message.headers.handshake.type.value) {
                case _k.HANDSHAKE_TYPE.ClientHello:
                {
                    handleClientHello(message);
                }
            }
        }

        function handleClientHello(message) {
            // Step 3: server receives ACK & CLIENT_HELLO
            console.log('[server]: received ACK & CLIENT_HELLO from client - [%s]', remoteAddress);

            // Step 3.1: server protocol version not supported
            if (message.client.version.value !== config.version) {
                console.log('[server]: protocol version not supported - [%s]', remoteAddress);
                socket.write(
                    createMessage({ 
                        contentType: _k.CONTENT_TYPE.Alert, 
                        version: config.version
                    })
                        .append(_k.BUFFERS.ALERT, {
                            level: _k.ALERT_LEVEL.FATAL, 
                            description: _k.ALERT_DESCRIPTION.PROTOCOL_VERSION 
                        })
                        .buffer
                );
                socket.end();
                return;
            }

            // Step 4: server sends SERVER_HELLO
            console.log('[server]: send SERVER_HELLO to client - [%s]', remoteAddress);
            sendServerHello(message);
        }

        function sendServerHello(message) {
            let s = new session();
            sessions.push(s);

            let negotiatedCipher = negotiateCipherSuite(
                message.client.ciphers.value, config.cipherSuites);

            // Step 4.1: server protocol version not supported
            if (negotiatedCipher === null) {
                console.log('[server]: unable to negotiate cipher suite - [%s]', remoteAddress);
                socket.write(
                    createMessage({ 
                        contentType: _k.CONTENT_TYPE.Alert, 
                        version: config.version
                    })
                        .append(_k.BUFFERS.ALERT, {
                            level: _k.ALERT_LEVEL.FATAL, 
                            description: _k.ALERT_DESCRIPTION.HANDSHAKE_FAILURE 
                        })
                        .buffer
                );
                socket.end();
                return;
            }

            let message = createMessage({
                contentType: _k.CONTENT_TYPE.Handshake,
                version: config.version
            })
                .append(_k.BUFFERS.HANDSHAKE_HEADER, { type: _k.HANDSHAKE_TYPE.ServerHello, length: 0 })
                .append(_k.BUFFERS.VERSION, { version: config.version })
                .append(_k.BUFFERS.RANDOM)
                .append(_k.BUFFERS.SESSION_ID, { id: s.id })
                .append(_k.BUFFERS.CIPHERS, { ciphers: [negotiatedCipher] })
                .append(_k.BUFFERS.COMPRESSION, { methods: [_k.COMPRESSION_METHODS.NULL] });

            socket.write(message.buffer);

            // Step 5: server sends CERTIFICATE
            console.log('[server]: send CERTIFICATE to client - [%s]', remoteAddress);
            sendCertificate();
        }

        function sendCertificate() {
            let message = createMessage({
                contentType: _k.CONTENT_TYPE.Handshake,
                version: config.version
            })
                .append(_k.BUFFERS.HANDSHAKE_HEADER, { type: _k.HANDSHAKE_TYPE.Certificate, length: 0 })
                .append(_k.BUFFERS.CERTIFICATE, { cert: config.cert });

            socket.write(message.buffer);

            // Step 6: server sends SERVER_KEY_EXCHANGE
            console.log('[server]: send SERVER_KEY_EXCHANGE to client - [%s]', remoteAddress);
            sendServerKeyExchange();
        }

        function sendServerKeyExchange() {
            let message = createMessage({
                contentType: _k.CONTENT_TYPE.Handshake,
                version: config.version
            })
                .append(_k.BUFFERS.HANDSHAKE_HEADER, { type: _k.HANDSHAKE_TYPE.ServerKeyExchange, length: 0 })
            // todo: add server key exchange parameters

            socket.write(message.buffer);

            // Step 7: server sends SERVER_HELLO_DONE
            console.log('[server]: send SERVER_HELLO_DONE to client - [%s]', remoteAddress);
            sendServerHelloDone();
        }

        function sendServerHelloDone() {
            let message = createMessage({
                contentType: _k.CONTENT_TYPE.Handshake,
                version: config.version
            })
                .append(_k.BUFFERS.HANDSHAKE_HEADER, { type: _k.HANDSHAKE_TYPE.DoneHello, length: 0 });

            socket.write(message.buffer);
        }

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
    };

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