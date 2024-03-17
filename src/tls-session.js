const { hexArray } = require('./utils');

function createSessionId() {
    return Buffer.from([0x00]);
}

function readSessionId(buffer) {
    return {
        _raw: hexArray(buffer),
        length: buffer.readUInt8(0)
    };
}

module.exports = { createSessionId, readSessionId }