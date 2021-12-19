
const config = require('./config')
module.exports = require(`./session/${config.session.provider}`)
