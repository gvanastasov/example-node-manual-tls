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
    },
    [_k.ContentType.Alert]: [
        _k.Annotations.RECORD_HEADER,
        _k.Annotations.ALERT,
    ],
}

function messageBuilder() {
    this.annotations = {};

    this.add = (annotation, args) => {
        this.annotations[annotation] = { ...args };
        return this;
    }

    this.build = () => {
        let buffer = Buffer.alloc(0);
        let { contentType } = this.annotations[_k.Annotations.RECORD_HEADER];
        switch (contentType) {
            case ContentType.Handshake:
            {
                let { type } = this.annotations[_k.Annotations.HANDSHAKE_HEADER];
                let template = MessageTemplates[contentType][type];
                if (!template) {
                    // todo: throw instead and catch upstream
                    console.error('No message template found for the given handshake type...');
                    break;
                }

                for (let annotation of template) {
                    let args = this.annotations[annotation];

                    if (!args) {
                        console.log('Missing protocol message annotation: ', annotation);
                        // todo: throw instead and catch upstream
                        continue;
                    }

                    let annotationBuffer = create(annotation, args);

                    buffer = Buffer.concat([buffer, annotationBuffer]);
                }

                // note: set the length of the message following the handshake header
                buffer.writeUInt16BE(buffer.length - 9, 6);
                break;
            }
            case ContentType.Alert:
            {
                let template = MessageTemplates[contentType];
                for (let annotation of template) {
                    let args = this.annotations[annotation];

                    if (!args) {
                        console.log('Missing protocol message annotation: ', annotation);
                        // todo: throw instead and catch upstream
                        continue;
                    }

                    let annotationBuffer = create(annotation, args);

                    buffer = Buffer.concat([buffer, annotationBuffer]);
                }
                break; 
            }
            default: 
            {
                // todo: throw instead and catch upstream
                console.error('Not implemented yet...');
                break;
            }
        }

        // note: set the length of the message following the record header
        buffer.writeUInt16BE(buffer.length - 5, 3);

        return buffer;
    }

    return this;
}

function parseMessage(hexString) {
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
        }
    }

    message[_k.Annotations.RECORD_HEADER] = read(_k.Annotations.RECORD_HEADER, context);

    let { contentType } = message[_k.Annotations.RECORD_HEADER];

    switch (contentType) {
        case ContentType.Handshake:
        {
            message[_k.Annotations.HANDSHAKE_HEADER] = read(_k.Annotations.HANDSHAKE_HEADER, context);

            let { type: handshakeType } = message[_k.Annotations.HANDSHAKE_HEADER];
            let template = MessageTemplates[contentType][handshakeType];

            if (!template) {
                // todo: throw instead and catch upstream
                console.error('No message template found for the given handshake type...');
                break;
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

    return message;
}

module.exports = { _k, messageBuilder, parseMessage }