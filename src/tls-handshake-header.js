const { hexArray, hexStrategyMixin } = require('./utils');
const dim = { 
    start: 5, 
    len: 4,
    get end() { return this.start + this.len; }
};

/**
 * @description refers to the type of handshake message being 
 * sent or received during the TLS handshake process. Each 
 * handshake message has a specific type that indicates its 
 * purpose in the handshake protocol
 */
const HandshakeType = {
    /**
     * Indicates that the hello process is complete
     */
    DoneHello: 0x00,

    /**
     * The client initiates the handshake process by sending 
     * a ClientHello message, indicating its intention to 
     * establish a secure connection.
     */
    ClientHello: 0x01,

    /**
     * The server responds to the ClientHello with a ServerHello 
     * message, indicating that it agrees to establish a secure 
     * connection and providing details about the selected 
     * cipher suite and other parameters.
     */
    ServerHello: 0x02,

    /**
     * The server sends its digital certificate to the client. 
     * The certificate contains the server's public key.
     */
    Certificate: 0x0B,

    /**
     * In some cases, the server sends additional key exchange 
     * parameters, especially when using certain key exchange 
     * algorithms.
     */
    ServerKeyExchange: 0x0C,

    /**
     * Both the client and server exchange Finished messages 
     * to confirm that the handshake is complete. This message 
     * is part of the process of transitioning to the 
     * application data phase.
     */
    Finished: 0x14,

    ...hexStrategyMixin
};

/**
 * @description
 * 1 byte - Handshake type
 * 2 bytes - Placeholder for message length
 * 
 * @param {number} type
 * @param {number} length
 * @returns 
 */
function create({ type, length }) {
    const header = Buffer.alloc(dim.len);
    header.writeUInt8(type, 0);
    header.writeUInt16BE(length, 1);
    return header;
}

/**
 * @description reads the handshake header from the buffer
 * @param {Buffer} buffer 
 * @returns an object representing the handshake header
 */
function read(buffer) {
    return {
        _raw: hexArray(buffer),
        type: HandshakeType.get(buffer.readUInt8(0)),
        length: buffer.readUInt16BE(1),
    };
}

module.exports = { HandshakeType, create, read };
