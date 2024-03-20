const Annotations = {
    ALERT: 'alert',
    CERTIFICATE: 'certificate',
    CIPHER_SUITES: 'cipherSuites',
    COMPRESSION_METHODS: 'compressionMethods',
    CURVE_INFO: 'curveInfo',
    EXTENSIONS: 'extensions',
    HANDSHAKE_HEADER: 'handshakeHeader',
    PUBLIC_KEY: 'publicKey',
    RANDOM: 'random',
    RECORD_HEADER: 'recordHeader',
    SESSION_ID: 'sessionId',
    SIGNATURE: 'signature',
    VERSION: 'version',
}

const modules = {
    [Annotations.ALERT]: require('./alert'),
    [Annotations.CERTIFICATE]: require('./certificate'),
    [Annotations.CIPHER_SUITES]: require('./cipher-suites'),
    [Annotations.COMPRESSION_METHODS]: require('./compression-methods'),
    [Annotations.CURVE_INFO]: require('./curve-info'),
    [Annotations.EXTENSIONS]: require('./extensions'),
    [Annotations.HANDSHAKE_HEADER]: require('./handshake-header'),
    [Annotations.PUBLIC_KEY]: require('./public-key'),
    [Annotations.RANDOM]: require('./random'),
    [Annotations.RECORD_HEADER]: require('./record-header'),
    [Annotations.SESSION_ID]: require('./session-id'),
    [Annotations.SIGNATURE]: require('./signature'),
    [Annotations.VERSION]: require('./version'),
}

const create = function(type, args) {
    return modules[type]?.create(args) || Buffer.alloc(0);
}

const read = function(type, message) {
    return modules[type].read(message);
}

module.exports = { Annotations, create, read };