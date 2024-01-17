const { hexArray, hexStrategyMixin } = require('./utils');
const { TLSVersion } = require('./tls-version');

const ContentType = {
    Handshake: 0x16,
    ChangeCipherSpec: 0x14,
    Alert: 0x15,
    ApplicationData: 0x17,

    ...hexStrategyMixin
};

/**
 * @description Creates a TLS record header.
 * 1 byte - Handshake type;
 * 2 bytes - TLS version;
 * 2 bytes - placeholder for length;
 * 
 * @param {number} contentType
 * @param {number} version
 * @param {number} length
 * @returns {Buffer} The TLS record header.
 */
function createRecordHeader(contentType, version, length) {
    const header = Buffer.alloc(5);
    header.writeUInt8(contentType, 0);
    header.writeUInt16BE(version, 1);
    header.writeUInt16BE(length, 3);
    return header;
}

function readRecordHeader(buffer) {
    const contentType = buffer.readUInt8(0);
    const version = buffer.readUInt16BE(1);
    const payloadLength = buffer.readUInt16BE(3);

    return {
        _raw: hexArray(buffer.subarray(0, 5)),
        contentType: ContentType.get(contentType),
        version: TLSVersion.get(version),
        payloadLength
    }
}

module.exports = { ContentType, createRecordHeader, readRecordHeader };
