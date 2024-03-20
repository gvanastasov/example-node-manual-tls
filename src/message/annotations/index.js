const Annotations = {
    ALERT: 'alert',
    CIPHER_SUITES: 'cipherSuites',
    COMPRESSION: 'compression',
    CERTIFICATE: 'certificate',
    CURVE_INFO: 'curveInfo',
    HANDSHAKE_HEADER: 'handshakeHeader',
    PUBLIC_KEY: 'publicKey',
    RANDOM: 'random',
    RECORD_HEADER: 'recordHeader',
    SESSION_ID: 'sessionId',
    SIGNATURE: 'signature',
    VERSION: 'version',
}

const modules = {
    [Annotations.HANDSHAKE_HEADER]: require('./handshake-annotation'),
    [Annotations.RECORD_HEADER]: require('./record-annotation'),
}

const create = function(type, args) {
    return modules[type]?.create(args) || Buffer.alloc(0);
}

const read = function(type, message) {
    return modules[type].read(message);
}

module.exports = { Annotations, create, read };