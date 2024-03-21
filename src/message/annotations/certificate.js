function create({ cert }) {
    const buffer = Buffer.alloc(3 + cert.length);
    buffer.writeUInt8(0, 0);
    buffer.writeUInt16BE(cert.length, 1);
    cert.copy(buffer, 3);
    return buffer;
}

function read(context) {
    const lengthBuffer = context.next(3);
    const length = lengthBuffer.readUInt16BE(1);
    const certBuffer = context.next(length);

    return { 
        _raw: Buffer.concat([lengthBuffer, certBuffer]),
        length,
        cert: certBuffer
    };
}

module.exports = {
    create,
    read,
}