const { ContentType, readRecordHeader } = require('./tls-record-header');
const { HandshakeType, readHandshakeHeader } = require('./tls-handshake-header');
const { readVersion } = require('./tls-version');
const { hexArray, removeRawProperties } = require('./utils');

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
    };
}

module.exports = { parseMessage }