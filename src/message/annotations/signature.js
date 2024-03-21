const crypto = require('crypto');
const { EncryptionAlgorithms, HashingFunctions } = require('./cipher-suites');

function create({ encryptionAlhorithm, encryptionKey, hashingFunction, data }) {
    const encrypted = crypto.publicEncrypt(
        encryptionKey, 
        Buffer.from(data, 'utf8'),
        {
            padding: (() => {
                switch (encryptionAlhorithm) {
                    case EncryptionAlgorithms.RSA:
                        return crypto.constants.RSA_PKCS1_PADDING;
                    default:
                        throw new Error('Unsupported encryption algorithm');
                }
            })(),
        });

    const hashed = crypto.createHash((() => {
        switch (hashingFunction) {
            case HashingFunctions.SHA256:
                return 'sha256';
            default:
                throw new Error('Unsupported hashing function');
        }
    })()).update(encrypted).digest();
    
    return hashed;
}

function read(message) {
    // todo: read signature
}

module.exports = {
    create,
    read,
}