function create({ key }) {
    const buffer = Buffer.alloc(1 + key.length);
    buffer.writeUInt8(key.length, 0);
    key.copy(buffer, 1);
    return buffer;
}

function read(message) {
    // todo: read certificate
}

module.exports = {
    create,
    read,
}