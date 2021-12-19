
var config = require('../config/default-config.json');
var environment = process.env.NODE_ENV || 'development';
if (!config[environment]) throw 'no config for env: ' + environment
module.exports = config[environment];
