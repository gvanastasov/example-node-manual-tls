/**
 * @description transforms a string into an array of hexadecimals strings
 * 
 * @param {string} hexString 
 * @returns 
 */
function hexArray(hexString) {
    return Array.from(hexString, byte => hexValue(byte))
}

function hexValue(byte) {
    return '0x' + byte.toString(16).padStart(2, '0');
}

const hexStrategyMixin = {
    get: function(hexadecimal) {
        return {
            _raw: hexValue(hexadecimal),
            name: this.getName(hexadecimal),
            value: hexadecimal,
        };
    },

    getName: function(hexadecimal) {
        return Object.keys(this).find(k => this[k] === hexadecimal);
    }
}

module.exports = { hexArray, hexValue, hexStrategyMixin };
