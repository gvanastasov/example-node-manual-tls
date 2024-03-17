const { hexArray, hexStrategyMixin } = require('./utils');

/**
 * @description algorithms that can be used to compress data exchanged during 
 * the TLS handshake and subsequent communication. Compression in TLS has been 
 * deprecated due to security concerns, and modern implementations typically 
 * do not support compression.
 * 
 */
const CompressionMethods = {
    /**
     * This method indicates that no compression is used.
     */
    NULL: 0x00,

    /**
     * Widely used compression algorithm that provides lossless data compression.
     */
    DEFLATE: 0x01,

    ...hexStrategyMixin
};

/**
 * @description Creates a TLS compression methods section.
 * @param {Array} methods The compression methods to include in the section.
 * @returns {Buffer} The TLS compression methods section.
 */
function createCompressionMethods(methods) {
    const length = methods.length;
    const buffer = Buffer.alloc(length + 1);
    buffer.writeUInt8(length, 0);
    methods.forEach((method, index) => {
        buffer.writeUInt8(method, index + 1);
    });
    return buffer;
}

/**
 * @description reads a buffer and converts to readable data
 * @param {Object} message
 * @returns {Buffer} The TLS compression methods section.
 */
function readCompressionMethods(message) {
    let buffer = message.context.buffer.next(1);
    let length = buffer.readUInt8(0);
    let methods = message.context.buffer.next(length);
    let compressionMethods = [];
    for (let i = 0; i < length; i++) {
        var value = methods.readUInt8(i);
        compressionMethods.push({
            _raw: hexArray(methods.subarray(i, i + 1)),
            name: CompressionMethods.getName(value),
            value,
        });
    }
    return compressionMethods;
}

module.exports = {
    CompressionMethods,
    createCompressionMethods,
    readCompressionMethods,
};