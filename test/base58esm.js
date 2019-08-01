// translate `main.js` to CommonJS
require = require('esm')(module);
module.exports = require('../base58.js');
