const ContentType = {
    Handshake: 0x16,
    ChangeCipherSpec: 0x14,
    Alert: 0x15,
    ApplicationData: 0x17,
};

const TLSVersion = {
    TLS_1_0: 0x0301,
    TLS_1_1: 0x0302,
    TLS_1_2: 0x0303,
    TLS_1_3: 0x0304,
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

module.exports = { ContentType, TLSVersion, createRecordHeader };
