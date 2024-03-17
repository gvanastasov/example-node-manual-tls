const { create, read, BUFFERS } = require('./tls');
const { ContentType, createRecordHeader, readRecordHeader } = require('./tls-record-header');
const { HandshakeType, createHandshakeHeader, readHandshakeHeader } = require('./tls-handshake-header');
const { createClientVersion, readVersion } = require('./tls-version');
const { createRandom, readRandom } = require('./tls-random');
const { createSessionId, readSessionId } = require('./tls-session');
const { createCipherSuites, readCipherSuites } = require('./tls-ciphers');
const { createCompressionMethods, readCompressionMethods } = require('./tls-compression');
const { hexArray, removeRawProperties } = require('./utils');

function createMessage({ contentType, version }) {
    const recordHeader = createRecordHeader(contentType, version, 0);
    this.buffers = [recordHeader];

    this.alert = ({ level, description }) => {
        this.buffers.push(create(BUFFERS.ALLERT, { level, description }));
        return this;
    };
    this.handshake = ({ handshakeType }) => {
        this.buffers.push(createHandshakeHeader(handshakeType, 0));
        return this;
    };
    this.version = ({ version }) => {
        this.buffers.push(createClientVersion(version));
        return this;
    };
    this.random = () => {
        this.buffers.push(createRandom());
        return this;
    };
    this.sessionId = () => {
        this.buffers.push(createSessionId());
        return this;
    };
    this.cipherSuites = ({ cs }) => {
        this.buffers.push(createCipherSuites(cs));
        return this;
    };
    this.compressionMethods = ({ methods }) => {
        this.buffers.push(createCompressionMethods(methods));
        return this;
    }
    this.build = () => {
        return Buffer.concat(this.buffers);
    }

    return this;
}

function parseMessage(hexString) {
    const buffer = Buffer.from(hexString, 'hex');

    const message = {
        _raw: hexArray(buffer),
        headers: {},
        context: {
            buffer: {
                value: buffer,
                pointer: 0,
                next(len) {
                    let current = this.pointer;
                    this.pointer += len;
                    return this.value.subarray(current, current + len);
                }
            },
        }
    }

    parseRecordHeader(message);

    // todo: lets add some debug controls for pretty printing...
    if (true) {
        delete(message.context.buffer);
        removeRawProperties(message);
        console.log(JSON.stringify(message, null, 2));
    }

    return message;
}

function parseRecordHeader(message) {
    let buffer = message.context.buffer.next(5);
    let record = readRecordHeader(buffer);

    message.headers.record = record;

    parsePayload(message);
}

function parsePayload(message) {
    switch (message.headers.record.contentType.value) {
        case ContentType.Handshake: 
        {
            parseHandshakeHeader(message);
            break;
        }
        case ContentType.Alert:
        {
            parseAlert(message);
            break;   
        }
        default: 
        {
            console.error('Not implemented yet...');
            break;
        }
    }
}

function parseHandshakeHeader(message) {
    let buffer = message.context.buffer.next(4);
    let handshake = readHandshakeHeader(buffer);

    message.headers.handshake = handshake;

    switch (handshake.type.value) {
        case HandshakeType.ClientHello:
        {
            parseClientHello(message);
            break;
        }
        default: 
        {
            console.error('Not implemented yet...');
            break;
        }
    }
}

function parseClientHello(message) {
    message.client = {
        version: readVersion(message.context.buffer.next(2)),
        random: readRandom(message.context.buffer.next(32)),
        sessionId: readSessionId(message.context.buffer.next(1)),
        cipherSuites: readCipherSuites(message),
        compressionMethods: readCompressionMethods(message)
    };
}

function parseAlert(message) {
    message.alert = read(BUFFERS.ALLERT, message);
}

module.exports = { createMessage, parseMessage }