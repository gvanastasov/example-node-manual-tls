const crypto = require('crypto');
const { EncryptionAlgorithms, HashingFunctions } = require('../message/annotations/cipher-suites');

function resolveHashingFunction(hashingFunction) {
    switch (hashingFunction) {
        case HashingFunctions.SHA256:
            return 'sha256';
        default:
            throw new Error('Unsupported hashing function');
    }
}

function resolveEncryptionAlgorithm(encryptionAlgorithm) {
    switch (encryptionAlgorithm) {
        case EncryptionAlgorithms.RSA:
            return crypto.constants.RSA_PKCS1_PADDING;
        default:
            throw new Error('Unsupported encryption algorithm');
    }
}

module.exports = {
    resolveHashingFunction,
    resolveEncryptionAlgorithm,
};