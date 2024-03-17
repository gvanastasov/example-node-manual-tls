const { create, read, BUFFERS } = require('./tls-buffers');
const { ContentType } = require('./tls-record-header');
const { HandshakeType } = require('./tls-handshake-header');
const { hexArray, removeRawProperties } = require('./utils');

function createMessage({ contentType, version }) {
    const recordHeader = create(BUFFERS.RECORD_HEADER, contentType, version, 0);
    this.buffers = [recordHeader];

    this.alert = ({ level, description }) => {
        this.buffers.push(create(BUFFERS.ALLERT, { level, description }));
        return this;
    };
    this.handshake = ({ handshakeType }) => {
        this.buffers.push(create(BUFFERS.HANDSHAKE_HEADER, handshakeType, 0));
        return this;
    };
    this.version = ({ version }) => {
        this.buffers.push(create(BUFFERS.VERSION, version));
        return this;
    };
    this.random = () => {
        this.buffers.push(create(BUFFERS.RANDOM));
        return this;
    };
    this.sessionId = () => {
        this.buffers.push(create(BUFFERS.SESSION_ID));
        return this;
    };
    this.cipherSuites = ({ cs }) => {
        this.buffers.push(create(BUFFERS.CIPHERS, cs));
        return this;
    };
    this.compressionMethods = ({ methods }) => {
        this.buffers.push(create(BUFFERS.COMPRESSION, methods));
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
    let record = read(BUFFERS.RECORD_HEADER, buffer);

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
    let handshake = read(BUFFERS.HANDSHAKE_HEADER, buffer);

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
        version: read(BUFFERS.VERSION, message.context.buffer.next(2)),
        random: read(BUFFERS.RANDOM, message.context.buffer.next(32)),
        sessionId: read(BUFFERS.SESSION_ID, message.context.buffer.next(1)),
        cipherSuites: read(BUFFERS.CIPHERS, message),
        compressionMethods: read(BUFFERS.COMPRESSION, message)
    };
}

function parseAlert(message) {
    message.alert = read(BUFFERS.ALLERT, message);
}

module.exports = { createMessage, parseMessage }