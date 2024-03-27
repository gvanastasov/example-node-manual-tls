function create({ data }) {
    return data;
}

function read(context) {
    return context.remaining();
}

module.exports = {
    create,
    read
}