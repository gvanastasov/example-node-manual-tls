const net = require('net');
const { ContentType, TLSVersion, createRecordHeader } = require('./record-header');

const serverAddress = 'localhost';
const serverPort = 3000;

function connect(address, port) {
  const client = new net.Socket();
  
  function ClientHello() {
    const recordHeader = createRecordHeader(ContentType.Handshake, TLSVersion.TLS_1_2, 0)
    
    return Buffer.concat([
      recordHeader
    ])
  }

  // Step 0: client sends SYN
  client.connect(serverPort, serverAddress, () => {
    console.log('Client: Connected to server');
  
    // Step 1: client receives SYN ACK
    client.on('data', data => {
      const message = data.toString();
      console.log(`Client: Received SYN ACK - ${message}`);
  
      // Step 2: client send ACK & ClientHello message
      let clientHello = ClientHello();
      client.write(clientHello);
  
      // Close the connection after sending the message
      client.end();
    });
  });
  
  client.on('end', () => {
    console.log('Client: Connection closed');
  });
  
  client.on('error', err => {
    console.error('Client: Error -', err.message);
  });
}