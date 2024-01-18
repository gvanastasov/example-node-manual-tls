const net = require('net');
const { ContentType, createRecordHeader }       = require('./tls-record-header');
const { HandshakeType, createHandshakeHeader }  = require('./tls-handshake-header');
const { TLSVersion, createClientVersion }       = require('./tls-version');
const { readMessage }                           = require('./tls-message');
const { TLS_HANDSHAKE_STATE } = require('./tls-handshake-state');

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

  // Step 1: client sends SYN to server
  console.log('[client]: send SYN');
  client.connect(port, address, () => {
    
    client.on('data', handleDataReceived);

    // Step 2: client receives SYN-ACK to server
    console.log('[client]: received SYN-ACK from server [%s%s]', address, port);

    var state = {
      current: TLS_HANDSHAKE_STATE.SEND_CLIENT_HELLO,

      [TLS_HANDSHAKE_STATE.SEND_CLIENT_HELLO]: function () {
        client.write(getClientHelloBuffer());
        this.current = TLS_HANDSHAKE_STATE.RECEIVED_SERVER_HELLO
      },

      [TLS_HANDSHAKE_STATE.RECEIVED_SERVER_HELLO]: function(message) {
        console.log("received sh: " + message)
      },

      next: function(message) {
        this[this.current](message);
      }
    }

    // Step 3: client send ACK & CLIENT_HELLO to server
    console.log('[client]: sends ACK & CLIENT_HELLO to server');
    state.next();

    function handleDataReceived(data) {
        // todo: parse data
        state.next(data);
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