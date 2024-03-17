const { create, read } = require('./tls-buffers');
const { CONTENT_TYPE, BUFFERS, HANDSHAKE_TYPE } = require('./tls-constants');
const { hexArray, removeRawProperties } = require('./utils');

function createMessage({ contentType, version }) {
    this.buffer = Buffer.alloc(0);
    this.append = (b, ...args) => {
        let buffer = create(b, ...args);
        this.buffer = Buffer.concat([this.buffer, buffer]);
        return this;
    }
    this.append(BUFFERS.RECORD_HEADER, contentType, version, 0);
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
        case CONTENT_TYPE.Handshake: 
        {
            parseHandshakeHeader(message);
            break;
        }
        case CONTENT_TYPE.Alert:
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
        case HANDSHAKE_TYPE.ClientHello:
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
    message.alert = read(BUFFERS.ALERT, message);
}

module.exports = { createMessage, parseMessage }