const BUFFERS = {
    ALERT: 'alert',
    CIPHERS: 'ciphers',
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
    [BUFFERS.ALERT]: require('./tls-alert'),
    [BUFFERS.CIPHERS]: require('./tls-ciphers'),
    [BUFFERS.COMPRESSION]: require('./tls-compression'),
    [BUFFERS.CERTIFICATE]: require('./tls-certificate'),
    [BUFFERS.CURVE_INFO]: require('./tls-curve-info'),
    [BUFFERS.HANDSHAKE_HEADER]: require('./tls-handshake-header'),
    [BUFFERS.PUBLIC_KEY]: require('./tls-public-key'),
    [BUFFERS.RANDOM]: require('./tls-random'),
    [BUFFERS.RECORD_HEADER]: require('./tls-record-header'),
    [BUFFERS.SESSION_ID]: require('./tls-session'),
    [BUFFERS.SIGNATURE]: require('./tls-signature'),
    [BUFFERS.VERSION]: require('./tls-version'),
}

const create = function(type, ...args) {
    return modules[type].create(...args);
}

const read = function(type, message) {
    return modules[type].read(message);
}

module.exports = {
    create,
    read,
    BUFFERS,
}