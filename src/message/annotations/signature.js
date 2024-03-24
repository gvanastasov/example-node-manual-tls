function create({ signature, encryptionAlgorithm, hashingFunction }) {
    const buffer = Buffer.alloc(4 + signature.length);
    buffer.writeUInt8(encryptionAlgorithm, 0);
    buffer.writeUInt8(hashingFunction, 1);
    buffer.writeUInt16BE(signature.length, 2);
    signature.copy(buffer, 4);
    return buffer;
}

function read(context) {
    const meta = context.next(4);
    const encryptionAlgorithm = meta.readUInt8(0);
    const hashingFunction = meta.readUInt8(1);
    const length = meta.readUInt16BE(2);
    const value = context.next(length);

    return {
        encryptionAlgorithm,
        hashingFunction,
        value,
    };
}

module.exports = {
    create,
    read,
}