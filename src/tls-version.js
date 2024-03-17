const { hexStrategyMixin } = require('./utils');

/**
 * @description primary TLS versions that have been widely adopted. 
 * However, it's important to note that using older versions like 
 * TLS 1.0 and TLS 1.1 is no longer recommended due to security 
 * vulnerabilities. TLS 1.2 and TLS 1.3 are considered more secure, 
 * and TLS 1.3 is the latest version
 */
const TLSVersion = {
    /**
     * @description first version of the TLS protocol, succeeding 
     * SSL 3.0. It introduced improvements over SSL 3.0 and aimed 
     * to enhance security in data transmissions over the internet.
     * 
     * Released: January 1999
     */
    TLS_1_0: 0x0301,

    /**
     * @description addressed vulnerabilities in TLS 1.0 and added 
     * support for new cryptographic algorithms. It introduced 
     * protection against cipher block chaining (CBC) attacks and 
     * deprecated weaker algorithms.
     * 
     * Released: April 2006
     */
    TLS_1_1: 0x0302,

    /**
     * @description further strengthened security by supporting 
     * advanced cryptographic algorithms and enhancing the 
     * negotiation process. It remains widely used and supported, 
     * providing a strong foundation for secure communication.
     * 
     * Released: August 2008
     */
    TLS_1_2: 0x0303,

    /**
     * @description is the latest version of the TLS protocol, 
     * introducing significant improvements in performance and 
     * security. It aims to reduce latency in the handshake 
     * process and remove support for insecure cryptographic 
     * algorithms. TLS 1.3 is designed to provide a more secure 
     * and efficient communication framework.
     * 
     * Released: March 2018
     */
    TLS_1_3: 0x0304,

    ...hexStrategyMixin,
};

/**
 * @description specifies the senders version of TSL
 * 2 bytes - for version [major, minor]
 * 
 * @param {int} version 
 * @returns 
 */
function create({ version }) {
    const buffer = Buffer.alloc(2);
    buffer.writeUInt16BE(version, 0);
    return buffer;
}

/**
 * @description reads the version from the buffer
 * @param {Buffer} buffer 
 * @returns 
 */
function read(buffer) {
    const version = buffer.readUInt16BE(0);
    return TLSVersion.get(version);
}

module.exports = { TLSVersion, create, read };