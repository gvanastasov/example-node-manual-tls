function create({ key }) {
    const buffer = Buffer.alloc(1 + key.length);
    buffer.writeUInt8(key.length, 0);
    key.copy(buffer, 1);
    return buffer;
}

function read(context) {
    const length = context.next(1).readUInt8(0);
    const key = context.next(length);

    return {
        _raw: Buffer.concat([Buffer.alloc(0), key]),
        length,
        value: key,
    };
}

module.exports = {
    create,
    read,
}