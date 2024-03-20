const { hexArray } = require('../../utils');

const EncryptionAlgorithms = {
    /**
     * @description RSA (Rivest-Shamir-Adleman)
     * a widely used public-key encryption algorithm named after 
     * its inventors Ron Rivest, Adi Shamir, and Leonard Adleman. 
     * It is one of the first public-key cryptosystems and is widely 
     * used for secure data transmission. In RSA, each party has 
     * a pair of keys: a public key and a private key. The public 
     * key is used for encryption and can be shared openly, while 
     * the private key is kept secret and is used for decryption. 
     * The keys are mathematically related in such a way that data 
     * encrypted with the public key can only be decrypted with 
     * the corresponding private key, and vice versa.
     */
    RSA: 0x04,
}

const HashingFunctions = {
    /**
     * @description SHA-256 is a cryptographic hash function that 
     * belongs to the SHA-2 (Secure Hash Algorithm 2) family. It 
     * generates a fixed-size (256-bit or 32-byte) output, regardless 
     * of the input size, making it suitable for a wide range of 
     * cryptographic applications.
     */
    SHA256: 0x01,
}

/**
 * Cipher suites are sets of cryptographic algorithms and 
 * parameters used to secure communication channels.During 
 * the TLS handshake, the client and server negotiate a 
 * cipher suite that both parties support and agree upon.
 * Cipher suites vary in terms of security and cryptographic 
 * strength. Stronger cipher suites provide better protection 
 * against attacks, but they may require more computational 
 * resources.
 * 
 * A cipher suite typically consists of several components:
 *      
 *      Key Exchange Algorithm - determines how client and 
 *          server agree on cryptographic keys.
 *      
 *      Authentication Algorithm - verifies the identity of 
 *          communication peers.
 *      
 *      Bulk Encryption Algorithm - encrypts and decrypts data 
 *          transferred between peers.
 *      
 *      Message Authentication Code (MAC) Algorithm - provides 
 *          integrity protection for transmitted data.
 */
const CipherSuits = {
    /**
     * @description 
     *      Key Exchange Algorithm: RSA
     *      Authentication Algorithm: RSA
     *      Bulk Encryption Algorithm: AES_128_CBC
     *      Message Authentication Code (MAC) Algorithm: SHA
     */
    TLS_RSA_WITH_AES_128_CBC_SHA: 0x002f,

    /**
     * @description
     *      Key Exchange Algorithm: ECDHE
     *      Authentication Algorithm: RSA
     *      Bulk Encryption Algorithm: AES_128_CBC
     *      Message Authentication Code (MAC) Algorithm: SHA
     */
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: 0xc013,

    // note: there are a lot more one can add...
};

/**
 * @description Creates a TLS cipher suites byte data
 * 
 * In the TLS protocol, the length of the cipher suites 
 * section can vary depending on the number of cipher 
 * suites included and their corresponding identifiers. 
 * The length of the cipher suites section is determined 
 * dynamically during the TLS handshake based on the 
 * number of cipher suites supported by both the client 
 * and the server. 
 * 
 * The cipher suites section starts with a 2-byte field 
 * indicating the length of the section in bytes. This 
 * length field allows the TLS parser to determine the 
 * boundaries of the cipher suites section and correctly 
 * extract the cipher suite identifiers.
 * 
 * Once the length of the cipher suites section is determined, 
 * it consists of a sequence of 2-byte cipher suite identifiers, 
 * with each identifier representing a specific combination 
 * of cryptographic algorithms and parameters.
 * 
 * @param {Array} ciphers
 * @returns {Buffer} The TLS cipher suite.
 */
function create({ ciphers }) {
    const suite = Buffer.alloc(2 + ciphers.length * 2);
    suite.writeUInt16BE(ciphers.length, 0);

    for (let i = 0; i < ciphers.length; i++) {
        suite.writeUInt16BE(ciphers[i], 2 + (i * 2));
    }

    return suite;
}

/**
 * @description reads a buffer and converts to readable data
 * @param {Object} context 
 * @returns 
 */
function read(context) {
    let buffer = context.next(2);
    let length = buffer.readUInt16BE(0);
    let cipherBuffer = context.next(length * 2);
    let cipherSuites = [];

    for (let i = 0; i < length; i++) {
        var value = cipherBuffer.readUInt16BE(i * 2);
        cipherSuites.push({
            _raw: hexArray(cipherBuffer.subarray(i * 2, (i * 2) + 2)),
            // name: CipherSuits.getName(value),
            value,
        });
    }
    
    return cipherSuites;
}

module.exports = { 
    EncryptionAlgorithms, 
    HashingFunctions, 
    CipherSuits, 
    create, 
    read 
};
