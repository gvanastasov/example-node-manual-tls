const net = require('net');
const os = require('os');
const { TLSVersion } = require('./tls-version');
const { ContentType } = require('./tls-record-header');
const { HandshakeType } = require('./tls-handshake-header');
const { ALERT_LEVEL, ALERT_DESCRIPTION } = require('./tls-alert');
const { createMessage, parseMessage } = require('./tls-message');
const { BUFFERS } = require('./tls-buffers');

function createServer({ hostname = 'localhost' } = {}) {
    const config = {
        version: TLSVersion.TLS_1_2,
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
                case ContentType.Handshake:
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
                case HandshakeType.ClientHello:
                {
                    handleClientHello(message);
                }
            }
        }

        function handleClientHello(message) {
            // Step 3: server receives ACK & CLIENT_HELLO
            console.log('[server]: received ACK & CLIENT_HELLO from client - [%s]', remoteAddress);

            if (message.client.version.value !== config.version) {
                console.log('[server]: protocol version not supported - [%s]', remoteAddress);
                socket.write(
                    createMessage({ 
                        contentType: ContentType.Alert, 
                        version: config.version 
                    })
                        .append(BUFFERS.ALERT, {
                            level: ALERT_LEVEL.FATAL, 
                            description: ALERT_DESCRIPTION.PROTOCOL_VERSION 
                        })
                        .buffer
                );
                socket.end();
                return;
            }

            // Step 4: server sends SERVER_HELLO
            // todo: send server hello
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