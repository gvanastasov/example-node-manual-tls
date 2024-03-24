const { generateRandomBytes } = require('../../utils/hex');

function create({ vector }) {
    return vector;
}

function read(context) {
    // todo: we should inffer this from the cipher suite instead of hardcoded
    return context.next(16);
}

module.exports = {
    create,
    read
}