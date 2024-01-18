const net = require('net');
const os = require('os');
const { TLS_HANDSHAKE_STATE } = require('./tls-handshake-state');

function createServer({ hostname = 'localhost' } = {}) {
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

        var state = TLS_HANDSHAKE_STATE.AWAITING_CLIENT_HELLO;
        var stateMachine = {
            [TLS_HANDSHAKE_STATE.AWAITING_CLIENT_HELLO]: handleClientHello,
        }

        function onConnectionDataReceive (data) {
            // todo: parse data
            stateMachine[state](data);
        };

        function onConnectionError(err) {
            console.log('[%s] connection error: %s', remoteAddress, err.message);  
        }

        function onConnectionClose() {  
            console.log('[%s] connection closed.', remoteAddress);  
        }

        function handleClientHello(data) {
            // Step 3: server receives ACK & CLIENT_HELLO
            console.log('[server]: received ACK & CLIENT_HELLO from client - [%s]', remoteAddress);
            
            // End
            // todo: close connection if protocol version not supported

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