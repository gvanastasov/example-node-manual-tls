const { ExtensionTypes } = require('./extensions');

const EllipticCurves = {
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
    const buffer = Buffer.alloc(1 + curve.length);
    buffer.writeUInt8(ExtensionTypes.named_curve, 0);
    
    for(let i = 0; i < curve.length; i++) {
        buffer.writeUInt8(curve[i], 1 + i);
    }

    return buffer;
}

function read(context) {
    const buffer = context.next(3);
    const type = buffer.readUInt8(0);
    const curve = buffer.readUInt8(2);

    return {
        type,
        curve,
    };
}

module.exports = { EllipticCurves, create, read };
