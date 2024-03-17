const net = require('net');
const os = require('os');
const { createMessage, parseMessage, _k } = require('./tls');

function createServer({ hostname = 'localhost' } = {}) {
    const config = {
        version: _k.PROTOCOL_VERSION.TLS_1_2,
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
            let message = createMessage({
                contentType: _k.CONTENT_TYPE.Handshake,
                version: config.version
            })
                .append(_k.BUFFERS.HANDSHAKE_HEADER, { type: _k.HANDSHAKE_TYPE.ServerHello, length: 0 })
                .append(_k.BUFFERS.VERSION, { version: config.version })
                .append(_k.BUFFERS.RANDOM)
                // todo: create session
                .append(_k.BUFFERS.SESSION_ID)
                .append(_k.BUFFERS.CIPHERS, { ciphers: _k.CIPHER_SUITES.TLS_RSA_WITH_AES_128_CBC_SHA })
                .append(_k.BUFFERS.COMPRESSION, { method: _k.COMPRESSION_METHODS.NULL });

            socket.write(message.buffer);

            // Step 5: server sends CERTIFICATE
            console.log('[server]: send CERTIFICATE to client - [%s]', remoteAddress);
            message = createMessage({
                contentType: _k.CONTENT_TYPE.Handshake,
                version: config.version
            })
                .append(_k.BUFFERS.HANDSHAKE_HEADER, { type: _k.HANDSHAKE_TYPE.Certificate, length: 0 })
                .append(_k.BUFFERS.CERTIFICATE);
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