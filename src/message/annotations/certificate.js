function create({ cert }) {
    const buffer = Buffer.alloc(3 + cert.length);
    buffer.writeUInt8(0, 0);
    buffer.writeUInt16BE(cert.length, 1);
    cert.copy(buffer, 3);
    return buffer;
}

function read(message) {
    // todo: read certificate
}

module.exports = {
    create,
    read,
}