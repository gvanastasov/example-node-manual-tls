function create({ data }) {
    return data;
}

function read(context) {
    return context.next(16);
}

module.exports = {
    create,
    read
}