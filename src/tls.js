const BUFFERS = {
    ALLERT: 'alert',
    RECORD_HEADER: 'recordHeader'
}

const modules = {
    [BUFFERS.ALLERT]: require('./tls-alert'),
    // [BUFFERS.RECORD_HEADER]: require('./tls-record-header'),
}

const create = function(type, args) {
    return modules[type].create(args);
}

const read = function(type, message) {
    return modules[type].read(message);
}

module.exports = {
    create,
    read,
    BUFFERS,
}