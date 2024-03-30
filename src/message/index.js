const { AlertLevel, AlertDescription } = require('./annotations/alert');
const { ContentType } = require('./annotations/record-header');
const { HandshakeType } = require('./annotations/handshake-header');
const { ProtocolVersion } = require('./annotations/version');
const { 
    EncryptionAlgorithms, 
    HashingFunctions,
    CipherSuits 
} = require('./annotations/cipher-suites');
const { CompressionMethods } = require('./annotations/compression-methods');
const { EllipticCurves } = require('./annotations/curve-info');
const { Annotations, create, read } = require('./annotations');

// barrel constants for TLS message
const _k = {
    AlertLevel,
    AlertDescription,
    Annotations,
    EncryptionAlgorithms,
    EllipticCurves,
    CipherSuits,
    ContentType,
    CompressionMethods,
    HandshakeType,
    HashingFunctions,
    ProtocolVersion,
    Dimensions: {
        RecordHeader: {
            Bytes: 5,
            ContentType: {
                Start: 0,
                End: 1,
            },
            Version: {
                Start: 1,
                End: 3,
            },
            Length: {
                Start: 3,
                End: 5,
            },
        },
    }
}

// protocol message templates
const MessageTemplates = {
    encrypted: [
        _k.Annotations.RECORD_HEADER,
        _k.Annotations.ENCRYPTION_IV,
        _k.Annotations.ENCRYPTED_DATA,
    ],
    [_k.ContentType.Handshake]: {
        [_k.HandshakeType.ClientHello]: [
            _k.Annotations.RECORD_HEADER,
            _k.Annotations.HANDSHAKE_HEADER,
            _k.Annotations.VERSION,
            _k.Annotations.RANDOM,
            _k.Annotations.SESSION_ID,
            _k.Annotations.CIPHER_SUITES,
            _k.Annotations.COMPRESSION_METHODS,
        ],
        [_k.HandshakeType.ServerHello]: [
            _k.Annotations.RECORD_HEADER,
            _k.Annotations.HANDSHAKE_HEADER,
            _k.Annotations.VERSION,
            _k.Annotations.RANDOM,
            _k.Annotations.SESSION_ID,
            _k.Annotations.CIPHER_SUITES,
            _k.Annotations.COMPRESSION_METHODS,
            // ...extensions
        ],
        [_k.HandshakeType.Certificate]: [
            _k.Annotations.RECORD_HEADER,
            _k.Annotations.HANDSHAKE_HEADER,
            _k.Annotations.CERTIFICATE,
        ],
        [_k.HandshakeType.ServerKeyExchange]: [
            _k.Annotations.RECORD_HEADER,
            _k.Annotations.HANDSHAKE_HEADER,
            _k.Annotations.CURVE_INFO,
            _k.Annotations.PUBLIC_KEY,
            _k.Annotations.SIGNATURE,
        ],
        [_k.HandshakeType.DoneHello]: [
            _k.Annotations.RECORD_HEADER,
            _k.Annotations.HANDSHAKE_HEADER,
        ],
        [_k.HandshakeType.ClientKeyExchange]: [
            _k.Annotations.RECORD_HEADER,
            _k.Annotations.HANDSHAKE_HEADER,
            _k.Annotations.PUBLIC_KEY,
        ],
        [_k.HandshakeType.ClientHandshakeFinished]: [
            _k.Annotations.RECORD_HEADER,
            _k.Annotations.HANDSHAKE_HEADER,
            _k.Annotations.VERIFY_DATA,
        ],
        [_k.HandshakeType.Finished]: [
            _k.Annotations.RECORD_HEADER,
            _k.Annotations.HANDSHAKE_HEADER,
            _k.Annotations.VERIFY_DATA,
        ],
    },
    [_k.ContentType.ChangeCipherSpec]: [
        _k.Annotations.RECORD_HEADER,
    ],
    [_k.ContentType.ApplicationData]: [
        _k.Annotations.APPLICATION_DATA,
    ],
    [_k.ContentType.Alert]: [
        _k.Annotations.RECORD_HEADER,
        _k.Annotations.ALERT,
    ],
}

const headersOrder = [
    _k.Annotations.RECORD_HEADER,
    _k.Annotations.HANDSHAKE_HEADER,
].reverse();

function messageBuilder() {
    this.headers = {};
    this.annotations = {};

    this.add = (annotation, args) => {
        if (annotation == _k.Annotations.RECORD_HEADER) {
            this.addHeader(annotation, args);
        } else if (annotation == _k.Annotations.HANDSHAKE_HEADER) {
            this.addHeader(annotation, args);
        } else {
            this.annotations[annotation] = { ...args };
        }

        return this;
    }

    this.addHeader = (type, args) => {
        this.headers[type] = { ...args };
        return this;
    }

    this.build = ({ format } = { format: 'buffer' }) => {
        let result = {
            data: {},
            buffer: Buffer.alloc(0),
        }

        for (let annotation in this.annotations) {
            let args = this.annotations[annotation];
            
            if (!args) {
                console.log('Missing protocol message annotation: ', annotation);
                // todo: throw instead and catch upstream
                continue;
            }

            let annotationBuffer = create(annotation, args);
            result.buffer = Buffer.concat([result.buffer, annotationBuffer]);

            if (format === 'object') {
                result.data[annotation] = { _raw: annotationBuffer, ...args };
            }
        }

        headersOrder.forEach((header) => {
            let args = this.headers[header];
            if (!args) {
                return;
            }

            let headerBuffer = create(header, { ...args, length: result.buffer.length });
            result.buffer = Buffer.concat([headerBuffer, result.buffer]);

            if (format === 'object') {
                result.data[header] = { _raw: headerBuffer, ...args };
            }
        });

        if (format === 'object') {
            return result;
        }

        return result.buffer;
    }

    return this;
}

function parseMessage(hexString, encrypted = false, decryptFunc = null) {
    const message = {
        _raw: hexString
    };

    const buffer = Buffer.from(hexString, 'hex');

    const context = {
        value: buffer,
        pointer: 0,
        next(len) {
            let current = this.pointer;
            this.pointer += len;
            return this.value.subarray(current, current + len);
        },
        remaining() {
            return this.value.subarray(this.pointer);
        }
    }

    // todo: error handling - missing header
    message[_k.Annotations.RECORD_HEADER] = read(_k.Annotations.RECORD_HEADER, context);
    let template = null;
    if (encrypted) {
        template = MessageTemplates.encrypted;
    } else {
        let { contentType } = message[_k.Annotations.RECORD_HEADER];

        switch (contentType) {
            case ContentType.Handshake:
            {
                // todo: error handling - missing header
                message[_k.Annotations.HANDSHAKE_HEADER] = read(_k.Annotations.HANDSHAKE_HEADER, context);

                let { type: handshakeType } = message[_k.Annotations.HANDSHAKE_HEADER];
                template = MessageTemplates[contentType][handshakeType];
                break;
            }
            case ContentType.ChangeCipherSpec:
            {
                template = MessageTemplates[contentType];
                break;
            }
            case ContentType.ApplicationData:
            {
                template = MessageTemplates[contentType];
                break;
            }
            case ContentType.Alert:
            {
                console.error('Not implemented yet...');
                break;
            }
            default: 
            {
                console.error('Not implemented yet...');
                break;
            }
        }
    }

    if (!template) {
        // todo: throw instead and catch upstream
        console.error('No message template found for the given handshake type...');
    }

    for (let annotation of template) {
        // dirty: we already read those from the buffer and the pointer is already moved
        if (annotation === _k.Annotations.RECORD_HEADER || 
            annotation === _k.Annotations.HANDSHAKE_HEADER) {
            continue;
        }

        try {
            message[annotation] = read(annotation, context);
        } catch (error) {
            // todo: throw instead and catch upstream
            console.error('Failed to read annotation: ', annotation);
        }
    }

    if (encrypted && decryptFunc) {
        let decryptedMessagePayload = decryptFunc({ iv: message[_k.Annotations.ENCRYPTION_IV], data: message[_k.Annotations.ENCRYPTED_DATA] });
        let decryptedMessage = parseMessage(Buffer.concat([message[_k.Annotations.RECORD_HEADER]._raw, decryptedMessagePayload]));

        return { ...message, ...decryptedMessage, _raw: hexString };
    }

    return message;
}

module.exports = { _k, messageBuilder, parseMessage }