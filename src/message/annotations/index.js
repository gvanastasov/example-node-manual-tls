const Annotations = {
    ALERT: 'alert',
    APPLICATION_DATA: 'applicationData',
    CERTIFICATE: 'certificate',
    CIPHER_SUITES: 'cipherSuites',
    COMPRESSION_METHODS: 'compressionMethods',
    CURVE_INFO: 'curveInfo',
    EXTENSIONS: 'extensions',
    ENCRYPTION_IV: 'encryptionIV',
    ENCRYPTED_DATA: 'encryptedData',
    HANDSHAKE_HEADER: 'handshakeHeader',
    PUBLIC_KEY: 'publicKey',
    RANDOM: 'random',
    RECORD_HEADER: 'recordHeader',
    SESSION_ID: 'sessionId',
    SIGNATURE: 'signature',
    VERSION: 'version',
    VERIFY_DATA: 'verifyData',
}

const modules = {
    [Annotations.ALERT]: require('./alert'),
    [Annotations.APPLICATION_DATA]: require('./application-data'),
    [Annotations.CERTIFICATE]: require('./certificate'),
    [Annotations.CIPHER_SUITES]: require('./cipher-suites'),
    [Annotations.COMPRESSION_METHODS]: require('./compression-methods'),
    [Annotations.CURVE_INFO]: require('./curve-info'),
    [Annotations.EXTENSIONS]: require('./extensions'),
    [Annotations.ENCRYPTION_IV]: require('./encryption-iv'),
    [Annotations.ENCRYPTED_DATA]: require('./encrypted-data'),
    [Annotations.HANDSHAKE_HEADER]: require('./handshake-header'),
    [Annotations.PUBLIC_KEY]: require('./public-key'),
    [Annotations.RANDOM]: require('./random'),
    [Annotations.RECORD_HEADER]: require('./record-header'),
    [Annotations.SESSION_ID]: require('./session-id'),
    [Annotations.SIGNATURE]: require('./signature'),
    [Annotations.VERSION]: require('./version'),
    [Annotations.VERIFY_DATA]: require('./verify-data'),
}

const create = function(annotation, args) {
    return modules[annotation]?.create(args) || Buffer.alloc(0);
}

const read = function(annotation, message) {
    return modules[annotation].read(message);
}

module.exports = { Annotations, create, read };