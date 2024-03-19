const { ALERT_LEVEL, ALERT_DESCRIPTION } = require('./tls-alert');
const { ENCRYPTION_ALGORITHMS, HASHING_FUNCTIONS, CipherSuits } = require('./tls-ciphers');

module.exports = {
    ALERT_LEVEL,
    ALERT_DESCRIPTION,
    ENCRYPTION_ALGORITHMS,
    ELLIPTIC_CURVES: require('./tls-curve-info').ELLIPTIC_CURVES,
    HASHING_FUNCTIONS,
    BUFFERS: require('./tls-buffers').BUFFERS,
    CIPHER_SUITES: CipherSuits,
    COMPRESSION_METHODS: require('./tls-compression').CompressionMethods,
    CONTENT_TYPE: require('./tls-record-header').ContentType,
    HANDSHAKE_TYPE: require('./tls-handshake-header').HandshakeType,
    PROTOCOL_VERSION: require('./tls-version').TLSVersion,
}