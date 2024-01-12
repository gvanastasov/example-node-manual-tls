const net = require('net');
const os = require('os');

function createServer({ hostname = 'localhost' } = {}) {
    const server = net.createServer();
    server.on('connection', handleConnection);
    
    console.log('[server]: created...')

    function handleConnection(socket) {
        socket.on('data', onConnectionDataReceive); 
        socket.on('error', onConnectionError);
        socket.once('close', onConnectionClose);

        var remoteAddress = socket.remoteAddress + ':' + socket.remotePort; 

        // Step 1: Server receives SYN from the client
        console.log('[server]: Received SYN from client - [%s]', remoteAddress);
        
        // Step 2: Server send SYN-ACK
        console.log('[server]: send SYN-ACK to client - [%s]', remoteAddress);
        const synAck = Buffer.from([0x16, 0x03, 0x03, 0x00, 0x04, 0x02]);
        socket.write(synAck);

        function onConnectionDataReceive (data) {
            // Step 3: Server receives ACK & HELLOWORLD
            console.log(`[client]: received SYNACK - ${data.toString('hex')}`);
        };

        function onConnectionError(err) {
            console.log('[%s] connection error: %s', remoteAddress, err.message);  
        }

        function onConnectionClose() {  
            console.log('[%s] connection closed.', remoteAddress);  
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