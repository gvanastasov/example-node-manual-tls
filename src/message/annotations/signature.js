const crypto = require('crypto');
const { EncryptionAlgorithms, HashingFunctions } = require('./cipher-suites');

function create({ encryptionAlhorithm, encryptionKey: { key, passphrase }, hashingFunction, data }) {
    const hashed = crypto.createHash((() => {
            switch (hashingFunction) {
                case HashingFunctions.SHA256:
                    return 'sha256';
                default:
                    throw new Error('Unsupported hashing function');
            }
        })()).update(data).digest();
    
    const encrypted = crypto.privateEncrypt(
        {
            key,
            passphrase,
            padding: (() => {
                switch (encryptionAlhorithm) {
                    case EncryptionAlgorithms.RSA:
                        return crypto.constants.RSA_PKCS1_PADDING;
                    default:
                        throw new Error('Unsupported encryption algorithm');
                }
            })(),
        },
        Buffer.from(hashed, 'utf8'));

    const buffer = Buffer.alloc(4 + encrypted.length);
    buffer.writeUInt8(encryptionAlhorithm, 0);
    buffer.writeUInt8(hashingFunction, 1);
    buffer.writeUInt16BE(encrypted.length, 2);
    encrypted.copy(buffer, 4);
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