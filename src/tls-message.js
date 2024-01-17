const { readRecordHeader } = require('./tls-record-header');
const { hexArray } = require('./utils');

function parseMessage(hexString) {
    // Convert the hex string to a Buffer
    const buffer = Buffer.from(hexString, 'hex');

    // Parse the record layer header
    const contentType = buffer.readUInt8(0);
    const version = buffer.readUInt16BE(1);
    const payloadLength = buffer.readUInt16BE(3);

    // Extract the payload based on the length
    const payload = buffer.subarray(5, 5 + payloadLength);

    const message = {
        _raw: hexArray(buffer),
        headers: {
            record: readRecordHeader(buffer),
        },
        payload: payload
    }

    console.log(JSON.stringify(message, null, 2));
}

module.exports = { parseMessage }