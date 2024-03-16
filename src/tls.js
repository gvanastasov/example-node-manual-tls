module.exports = {
    states: require('./tls-handshake-state'),
    versions: require('./tls-version'),
    parseMessage: require('./tls-message').parseMessage
}