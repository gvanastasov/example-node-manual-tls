const crypto = require('crypto');
const { _k } = require('.');

/**
 * @description The handshake digest is a value computed during the TLS handshake process
 * that is used to derive the master secret and other keys used in the TLS handshake.
 * The handshake digest is computed by hashing the handshake messages exchanged between
 * the client and server and then using the resulting hash to verify the integrity of
 * communication.
 * 
 * @returns {Object} handshakeDigest
 */
function handshakeDigest() {
    this.value = Buffer.alloc(0);
    
    /**
     * @description Increses the value of the digest. RecordHeader is omit
     * because its always the same length/value during handshake process and
     * will produce 0 impact on the digest.
     * 
     * @param {Buffer} message 
     */
    this.in = (message) => {
        const payload = message.subarray(_k.Dimensions.RecordHeader.Bytes);
        this.value = Buffer.concat([this.value, payload]);
    }

    /**
     * @description Computes the handshake digest using the provided hashing function
     * and seed data. The digest is used to derive the master secret and other keys
     * used in the TLS handshake.
     * 
     * 3 stages of the key derivation process:
     *      1. Hashing
     *      2. Seeding
     *      3. Iterative Key Derivation
     * 
     * @param {Object} param0 
     * @returns 12 bytes of data
     */
    this.compute = ({ hashingFunction, seedData, secret }) => {
        /**
         * The handshake digest is first hashed using SHA-256 to ensure that it has 
         * a fixed-size representation and to provide a uniformly distributed output. 
         * This hash operation ensures that the input to the subsequent key derivation 
         * process has a consistent format and length.
         */
        const hash = crypto.createHash(hashingFunction).update(this.value).digest();
        
        /**
         * The hash of the handshake digest is concatenated with additional data (in 
         * this case, input seedData string) to form the seed. This seed serves as the 
         * initial input to the key derivation function.
        */
        const seed = Buffer.concat([Buffer.from(seedData), hash]);
        let a0 = seed;
        const a1 = crypto.createHmac(hashingFunction, secret).update(a0).digest();

        /**
         * The key derivation process involves multiple iterations of HMAC-SHA256 
         * (Hash-based Message Authentication Code using SHA-256). Each iteration 
         * produces a new intermediate key (a1) based on the previous iteration's 
         * output (a0) and the seed. The final output (p1) is derived from the last 
         * iteration's output concatenated with the seed.
         */
        const p1 = crypto.createHmac(hashingFunction, secret).update(Buffer.concat([a1, seed])).digest();

        // todo: use constant for the length (12 is by protocol)
        return p1.subarray(0, 12);
    }
    
    return this;
}

module.exports = { handshakeDigest };