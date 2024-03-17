const { hexArray, hexStrategyMixin } = require('./utils');

const CipherSuits = {
    TLS_RSA_WITH_AES_128_CBC_SHA: 0x002f,

    // note: there are a lot more one can add...

    ...hexStrategyMixin
};

/**
 * @description Creates a TLS cipher suite.
 * 
 * @param {Array} cipherSuite
 * @returns {Buffer} The TLS cipher suite.
 */
function createCipherSuites(cipherSuite) {
    const suite = Buffer.alloc(2 + cipherSuite.length * 2);
    suite.writeUInt16BE(cipherSuite.length, 0);

    for (let i = 0; i < cipherSuite.length; i++) {
        suite.writeUInt16BE(cipherSuite[i], 2 + (i * 2));
    }

    return suite;
}

function readCipherSuites(message) {
    let buffer = message.context.buffer.next(2);
    let length = buffer.readUInt16BE(0);
    let cipherBuffer = message.context.buffer.next(length * 2);
    let cipherSuites = [];

    for (let i = 0; i < length; i++) {
        var value = cipherBuffer.readUInt16BE(i * 2);
        cipherSuites.push({
            _raw: hexArray(cipherBuffer.subarray(i * 2, (i * 2) + 2)),
            name: CipherSuits.getName(value),
            value,
        });
    }
    
    return cipherSuites;
}

module.exports = { CipherSuits, createCipherSuites, readCipherSuites };
