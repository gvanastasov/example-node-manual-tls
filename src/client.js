const net = require('net');
const { ContentType, createRecordHeader }       = require('./tls-record-header');
const { HandshakeType, createHandshakeHeader }  = require('./tls-handshake-header');
const { createClientVersionBuffer }             = require('./tls-client-version');
const { TLSVersion }                            = require('./tls-version');

function connect(address, port) {
  const client = new net.Socket();
  
  function getClientHelloBuffer() {
    const recordHeader    = createRecordHeader(ContentType.Handshake, TLSVersion.TLS_1_2, 0)
    const handshakeHeader = createHandshakeHeader(HandshakeType.ClientHello, 0);
    const clientVersion   = createClientVersionBuffer(TLSVersion.TLS_1_2);
 
    return Buffer.concat([
      recordHeader,
      handshakeHeader,
      clientVersion,
    ]);
  }

  // Step 1
  console.log('[client]: send SYN');
  client.connect(port, address, () => {
    console.log('[client]: connected...');
  
    client.on('data', data => {
      // Step 2

      const buffer = Buffer.from(data, 'hex');
      console.log(`[client]: received SYNACK - ${buffer}`);

      // Split the buffer into individual bytes
      const bytes = Array.from(buffer);
      console.log(`[client]: received SYNACK - ${bytes}`);

      // Log the result
      console.log('Bytes:', bytes);
      console.log(`[client]: received SYNACK - ${data.toString('hex')}`);
  
      // Step 3
      console.log(`[client]: send ACK & CLIENTHELLO - ${data.toString('hex')}`);
      let clientHello = getClientHelloBuffer();
      client.write(clientHello);
  
      // Close the connection after sending the message
      // client.end();
    });
  });
  
  client.on('end', () => {
    console.log('[client]: connection closed');
  });
  
  client.on('error', err => {
    console.error('[client]: error -', err.message);
  });
}

module.exports = { connect }