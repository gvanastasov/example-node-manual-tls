const { createMessage, parseMessage, _k } = require('./tls');

function context(data) {
    this.req = req(data);
    this.res = res();
}

function req(data) {
    this.message = parseMessage(data);
    return this;
}

function res() {
    return this;
}

module.exports = { context }