const { ALERT_LEVEL, ALERT_DESCRIPTION } = require('./tls-alert');

module.exports = {
    ALERT_LEVEL,
    ALERT_DESCRIPTION,
    BUFFERS: require('./tls-buffers').BUFFERS,
    CIPHER_SUITES: require('./tls-ciphers').CipherSuits,
    COMPRESSION_METHODS: require('./tls-compression').CompressionMethods,
    CONTENT_TYPE: require('./tls-record-header').ContentType,
    HANDSHAKE_TYPE: require('./tls-handshake-header').HandshakeType,
    PROTOCOL_VERSION: require('./tls-version').TLSVersion,
}