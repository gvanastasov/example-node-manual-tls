const { HandshakeType } = require('../tls-handshake-header');
const { Annotations, create, read } = require('./annotations');

const ContentType = {
    /**
     * Used for exchanging cryptographic parameters and 
     * keying material during the TLS handshake process. 
     * Handshake messages include various types such as 
     * ClientHello, ServerHello, Certificate, Finished, 
     * etc. These messages play a crucial role in 
     * establishing a secure connection between the client 
     * and server.
     */
    Handshake: 0x16,

    /**
     * Used to signal a change in the cryptographic parameters 
     * for communication. This typically follows the handshake 
     * messages and indicates that subsequent records will be 
     * protected using the negotiated algorithms and keys.
     */
    ChangeCipherSpec: 0x14,

    /**
     * Used for conveying error messages or warnings between the 
     * client and server. Alert messages can indicate issues such 
     * as unexpected closure of the connection, certificate problems, 
     * or protocol-related errors. Alerts help in communicating 
     * problems that may require immediate attention.
     */
    Alert: 0x15,

    /**
     * Used for carrying the actual application data. Once the 
     * handshake is complete and the secure channel is established, 
     * application data, such as HTTP requests or responses in the 
     * case of HTTPS, is transmitted using this content type.
     */
    ApplicationData: 0x17,
};

const MessageTemplates = {
    [ContentType.Handshake]: {
        [HandshakeType.ClientHello]: [
            Annotations.RECORD_HEADER,
            Annotations.HANDSHAKE_HEADER,
            Annotations.VERSION,
            Annotations.RANDOM,
            Annotations.SESSION_ID,
            Annotations.CIPHER_SUITES,
            Annotations.COMPRESSION,
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
        let { contentType } = this.annotations[Annotations.RECORD_HEADER];
        switch (contentType) {
            case ContentType.Handshake:
            {
                let { type } = this.annotations[Annotations.HANDSHAKE_HEADER];
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

    message.headers.record = read(Annotations.RECORD_HEADER, context);

    let contentType = message.headers.record.contentType;

    switch (contentType) {
        case ContentType.Handshake: 
        {
            message.headers.handshake = read(Annotations.HANDSHAKE_HEADER, context);

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

module.exports = { ContentType, messageBuilder, parseMessage }