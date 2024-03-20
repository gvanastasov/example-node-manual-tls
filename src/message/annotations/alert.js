const { hexStrategyMixin } = require('../../utils');

/**
 * @description The TLS alert level codes.
 */
const AlertLevel = {
    WARNING: 0x01,
    FATAL: 0x02,
}

/**
 * @description The TLS alert description codes.
 */
const AlertDescription = {
    CLOSE_NOTIFY: 0x00,
    UNEXPECTED_MESSAGE: 0x0A,
    BAD_RECORD_MAC: 0x14,
    DECRYPTION_FAILED: 0x15,
    RECORD_OVERFLOW: 0x16,
    DECOMPRESSION_FAILURE: 0x1E,
    HANDSHAKE_FAILURE: 0x28,
    NO_CERTIFICATE: 0x29,
    BAD_CERTIFICATE: 0x2A,
    UNSUPPORTED_CERTIFICATE: 0x2B,
    CERTIFICATE_REVOKED: 0x2C,
    CERTIFICATE_EXPIRED: 0x2D,
    CERTIFICATE_UNKNOWN: 0x2E,
    ILLEGAL_PARAMETER: 0x2F,
    UNKNOWN_CA: 0x30,
    ACCESS_DENIED: 0x31,
    DECODE_ERROR: 0x32,
    DECRYPT_ERROR: 0x33,
    EXPORT_RESTRICTION: 0x3C,
    PROTOCOL_VERSION: 0x46,
    INSUFFICIENT_SECURITY: 0x47,
    INTERNAL_ERROR: 0x50,
    USER_CANCELED: 0x5A,
    NO_RENEGOTIATION: 0x64,
    UNSUPPORTED_EXTENSION: 0x6E,
    CERTIFICATE_UNOBTAINABLE: 0x6F,
    UNRECOGNIZED_NAME: 0x70,
    BAD_CERTIFICATE_STATUS_RESPONSE: 0x71,
    BAD_CERTIFICATE_HASH_VALUE: 0x72,
    UNKNOWN_PSK_IDENTITY: 0x73,
    NO_APPLICATION_PROTOCOL: 0x78,
}

function create({ level, description }) {
    const buffer = Buffer.alloc(2);
    buffer.writeUInt8(level, 0);
    buffer.writeUInt8(description, 1);
    return buffer;
}

function read(message) {
    var buffer = message.context.buffer.next(2);
    return {
        level: AlertLevel.get(buffer.readUInt8(0)),
        description: AlertDescription.get(buffer.readUInt8(1)),
    };
}

module.exports = {
    ALERT_LEVEL: AlertLevel,
    ALERT_DESCRIPTION: AlertDescription,
    create,
    read
};