function create({ data }) {
    if (typeof(data) === 'string') {
        return Buffer.from(data);
    }

    if (data instanceof Buffer) {
        return data;
    }

    throw new Error('Invalid data type');
}

function read(context) {
    return context.remaining();
}

module.exports = {
    create,
    read
}