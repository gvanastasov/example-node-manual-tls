const { AlertLevel, AlertDescription } = require('./annotations/alert');
const { ContentType } = require('./annotations/record-header');
const { HandshakeType } = require('./annotations/handshake-header');
const { Annotations, create, read } = require('./annotations');

// barrel constants for TLS message
const _k = {
    AlertLevel,
    AlertDescription,
    Annotations,
    ContentType,
    HandshakeType,
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
            _k.Annotations.COMPRESSION,
        ]
    }
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

        return buffer;
    }

    return this;
}

function parseMessage(hexString) {
    const buffer = Buffer.from(hexString, 'hex');
    
    const message = {
        headers: {},
    };

    const context = {
        value: buffer,
        pointer: 0,
        next(len) {
            let current = this.pointer;
            this.pointer += len;
            return this.value.subarray(current, current + len);
        }
    }

    message.headers.record = read(_k.Annotations.RECORD_HEADER, context);

    let contentType = message.headers.record.contentType;

    switch (contentType) {
        case ContentType.Handshake:
        {
            message.headers.handshake = read(_k.Annotations.HANDSHAKE_HEADER, context);

            let handshakeType = message.headers.handshake.type;
            let template = MessageTemplates[contentType][handshakeType];

            if (!template) {
                // todo: throw instead and catch upstream
                console.error('No message template found for the given handshake type...');
                break;
            }

            for (let annotation of template) {
                message[annotation] = read(annotation, context);
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