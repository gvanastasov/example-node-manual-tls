// barrel file for tls module
module.exports = {
    _k: require('./tls-constants'),
    ...require('./tls-buffers'),
    ...require('./tls-message'),
};
