const net = require('net');
const { ContentType, createRecordHeader }       = require('./tls-record-header');
const { HandshakeType, createHandshakeHeader }  = require('./tls-handshake-header');
const { TLSVersion, createClientVersion }       = require('./tls-version');
const { parseMessage }                          = require('./tls-message');

function connect(address, port) {
  const client = new net.Socket();
  
  function getClientHelloBuffer() {
    const recordHeader    = createRecordHeader(ContentType.Handshake, TLSVersion.TLS_1_2, 0)
    const handshakeHeader = createHandshakeHeader(HandshakeType.ClientHello, 0);
    const clientVersion   = createClientVersion(TLSVersion.TLS_1_2);
 
    return Buffer.concat([
      recordHeader,
      handshakeHeader,
      clientVersion,
    ]);
  }

  // Step 1
  console.log('[client]: send SYN');
  client.connect(port, address, () => {
    client.on('data', handleDataReceived);

    function handleDataReceived(data) {
        // Step 2
        console.log(`[client]: received SYN-ACK`);
        parseMessage(data);
  
        // Step 3
        console.log(`[client]: send ACK & CLIENTHELLO - ${data.toString('hex')}`);
        let clientHello = getClientHelloBuffer();
        client.write(clientHello);
    
        // Close the connection after sending the message
        // client.end();
    }
  });
  
  client.on('end', () => {
    console.log('[client]: connection closed');
  });
  
  client.on('error', err => {
    console.error('[client]: error -', err.message);
  });
}

module.exports = { connect }