const { EXTENSION_TYPES } = require('./tls-extensions');

const ELLIPTIC_CURVES = {
    /**
     * @description Curve25519
     * 
     * A curve designed by Daniel J. Bernstein for use in the 
     * Diffie-Hellman key exchange. It offers strong security 
     * properties and excellent performance, making it popular 
     * in modern cryptographic protocols, including TLS.
     * 
     */
    'x25519': [0x00, 0x1D],

    // ... others
}

function create({ curve }) {
    const buffer = Buffer.alloc(3 + curve.length);
    buffer.writeUInt8(0, EXTENSION_TYPES.named_curve);
    buffer.writeUInt16BE(curve.length, 1);
    return buffer;
}

function read(message) {
    const buffer = message.context.buffer.next(3);
    const type = buffer.readUInt8(0);
    const curve = buffer.readUInt16BE(1);

    return {
        type,
        curve: curve.toString(16),
    };
}

module.exports = { ELLIPTIC_CURVES, create, read };