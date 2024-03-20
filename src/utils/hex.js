/**
 * @description transforms a string into an array of hexadecimals strings
 * 
 * @param {string} str 
 * @returns 
 */
function hexArray(str) {
    return Array.from(str, byte => hexValue(byte))
}

function hexValue(byte) {
    return '0x' + byte.toString(16).padStart(2, '0');
}

function generateRandomBytes(length) {
    return Array.from({ length }, () => Math.floor(Math.random() * 256));
}

module.exports = {
    hexArray,
    hexValue,
    generateRandomBytes
}