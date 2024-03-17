const BUFFERS = {
    ALERT: 'alert',
    CIPHERS: 'ciphers',
    COMPRESSION: 'compression',
    CERTIFICATE: 'certificate',
    HANDSHAKE_HEADER: 'handshakeHeader',
    RANDOM: 'random',
    RECORD_HEADER: 'recordHeader',
    SESSION_ID: 'sessionId',
    VERSION: 'version',
}

const modules = {
    [BUFFERS.ALERT]: require('./tls-alert'),
    [BUFFERS.CIPHERS]: require('./tls-ciphers'),
    [BUFFERS.COMPRESSION]: require('./tls-compression'),
    [BUFFERS.CERTIFICATE]: require('./tls-certificate'),
    [BUFFERS.HANDSHAKE_HEADER]: require('./tls-handshake-header'),
    [BUFFERS.RANDOM]: require('./tls-random'),
    [BUFFERS.RECORD_HEADER]: require('./tls-record-header'),
    [BUFFERS.SESSION_ID]: require('./tls-session'),
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