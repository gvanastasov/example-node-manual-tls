const { readRecordHeader } = require('./tls-record-header');
const { hexArray } = require('./utils');

function readMessage(hexString) {
    // Convert the hex string to a Buffer
    const buffer = Buffer.from(hexString, 'hex');

    var record = readRecordHeader(buffer);

    // Extract the payload based on the length
    const payload = buffer.subarray(5, 5 + record.payloadLength);

    const message = {
        _raw: hexArray(buffer),
        headers: {
            record,
        },
        payload: payload
    }

    console.log(JSON.stringify(message, null, 2));
}

module.exports = { readMessage }