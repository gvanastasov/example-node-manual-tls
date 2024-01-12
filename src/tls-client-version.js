/**
 * @description specifies the senders version of TSL
 * 2 bytes - for version [major, minor]
 * 
 * @param {int} version 
 * @returns 
 */
function createClientVersionBuffer(version) {
    const buffer = Buffer.alloc(2);
    buffer.writeUInt16BE(version, 0);
    return buffer;
}

module.exports = { createClientVersionBuffer };
