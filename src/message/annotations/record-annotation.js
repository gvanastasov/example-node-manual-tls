const { hexArray, hexStrategyMixin } = require('../../utils');

/**
 * @description Creates a TLS record header. The content types 
 * specified in the record header of a TLS message indicate the 
 * type of content that follows in the payload.
 * 
 * Reserved 5 bytes
 * 1 - Handshake type;
 * 2 - TLS version;
 * 2 - placeholder for length;
 * 
 * @example
 * 0x16 0x03 0x01 0x00 0xa5
 * 
 * @param {number} contentType
 * @param {number} version
 * @param {number} length
 * @returns {Buffer} The TLS record header.
 */
function create({ contentType, version, length }) {
    const header = Buffer.alloc(5);
    header.writeUInt8(contentType, 0);
    header.writeUInt16BE(version, 1);
    header.writeUInt16BE(length, 3);
    return header;
}

/**
 * @description 
 * @param {Object} context
 * @returns an object representing record header
 */
function read(context) {
    const buffer = context.next(5);
    const contentType = buffer.readUInt8(0);
    const version = buffer.readUInt16BE(1);
    const payloadLength = buffer.readUInt16BE(3);

    // todo: add pretty print for contentType and version
    return {
        _raw: hexArray(buffer),
        contentType: contentType,
        version: version,
        payloadLength
    };
}

module.exports = { create, read };