const { hexArray, hexStrategyMixin } = require('./utils');
const { TLSVersion } = require('./tls-version');

const ContentType = {
    /**
     * Used for exchanging cryptographic parameters and 
     * keying material during the TLS handshake process. 
     * Handshake messages include various types such as 
     * ClientHello, ServerHello, Certificate, Finished, 
     * etc. These messages play a crucial role in 
     * establishing a secure connection between the client 
     * and server.
     */
    Handshake: 0x16,

    /**
     * Used to signal a change in the cryptographic parameters 
     * for communication. This typically follows the handshake 
     * messages and indicates that subsequent records will be 
     * protected using the negotiated algorithms and keys.
     */
    ChangeCipherSpec: 0x14,

    /**
     * Used for conveying error messages or warnings between the 
     * client and server. Alert messages can indicate issues such 
     * as unexpected closure of the connection, certificate problems, 
     * or protocol-related errors. Alerts help in communicating 
     * problems that may require immediate attention.
     */
    Alert: 0x15,

    /**
     * Used for carrying the actual application data. Once the 
     * handshake is complete and the secure channel is established, 
     * application data, such as HTTP requests or responses in the 
     * case of HTTPS, is transmitted using this content type.
     */
    ApplicationData: 0x17,

    ...hexStrategyMixin
};

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
function createRecordHeader(contentType, version, length) {
    const header = Buffer.alloc(5);
    header.writeUInt8(contentType, 0);
    header.writeUInt16BE(version, 1);
    header.writeUInt16BE(length, 3);
    return header;
}

/**
 * @description reads a buffer and converts to readable data
 * @param {Buffer} buffer
 * @returns an object representing record header
 */
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
