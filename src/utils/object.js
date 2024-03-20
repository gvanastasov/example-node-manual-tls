function findProperty(obj, property) {
    return Object.keys(obj).find(k => obj[k] === property);
}

function removeProperty(obj, property) {
    for (let key in obj) {
        if (obj.hasOwnProperty(key)) {
            if (key === property) {
                delete obj[key];
            } else if (typeof obj[key] === 'object') {
                removeProperty(obj[key]);
            }
        }
    }
}

module.exports = {
    findProperty,
    removeProperty
}
