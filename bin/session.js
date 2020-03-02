const { Client } = require('pg')
    ,useragent = require('useragent');

const client = new Client({
    user: 'auth',
    host: 'localhost',
    database: 'horizon',
    password: 'auth',
    port: 5432,
})

client.connect()

function newSession(redirect_url, user_agent, verify, done) {
    const sql = 'insert into auth_session(redirect_url, user_agent, client_verify) values ($1, $2, $3) returning session_id'
    client.query(sql, [redirect_url, user_agent, verify])
        .then(res => {
            done(null, res.rows[0].session_id)
        })
        .catch(e => {
            done(`create session: ${e}`)
        })
}

function retrieveSession(session_id, done, next) {
    const sql = 'select session_id, user_agent, redirect_url, auth_info, char_info, error, created, updated from auth_session where session_id = $1' // SQLI
    client.query(sql, [session_id])
        .then(result => {
            let session = result.rows[0]
            if (!session)
                return done(`state ${session_id}`)
            next(session, done)
        })
        .catch(e => done(`get session: ${e}`))
}

function updateSession(session, data) {
    data.updated = new Date()
    let fields = []
    let i = 0
    Object.keys(data).forEach(f => fields.push(`${f}=$${++i}`))
    const sql = `update auth_session set ${fields.join(', ')} where session_id = $${++i}`
    const values = Object.values(data)
    values.push(session.session_id)
    client.query(sql, values)
        .catch(e => console.log(`error updating auth_session: ${e}`))
}

function completeSession(verify, user_agent, done) {
    const device = get_device(user_agent)
    let sql = 'select * from user_sign_in($1, $2, $3)' // SQLI
    client.query(sql, [verify, user_agent, device])
        .then(result => {
            done(null, result.rows[0].user_sign_in)
        })
        .catch(e => done(`user sign in: ${e}`))
}

function get_device(user_agent) {
    let ua =  useragent.parse(user_agent);
    return `${ua.family}-${ua.os.family}${ua.os.major}-${ua.device.family}`.toLowerCase()
}

module.exports.newSession = newSession;
module.exports.retrieveSession = retrieveSession;
module.exports.completeSession = completeSession;
module.exports.updateSession = updateSession;

