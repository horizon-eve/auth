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

function newSession(redirect_url, user_agent, done) {
    let sql = 'insert into auth_session(redirect_url, user_agent) values ($1, $2) returning session_id'
    client.query(sql, [redirect_url, user_agent])
        .then(res => {
            done(null, res.rows[0].session_id)
        })
        .catch(e => {
            done(`create session: ${e}`)
        })
}

function retrieveSession(session_id, done, next) {
    let sql = 'select session_id, user_agent, redirect_url, auth_info, char_info, error, created, updated from auth_session where session_id = $1' // SQLI
    client.query(sql, [session_id])
        .then(result => {
            let session = result.rows[0]
            if (!session)
                return done(`state ${session_id}`)
            next(session, done)
        })
        .catch(e => done(`get session: ${e}`))
}

function completeSession(session, auth_info, char_info, done) {
    let ua =  useragent.parse(session.user_agent);
    const device = `${ua.family}-${ua.os.family}${ua.os.major}-${ua.device.family}`.toLowerCase()
    let sql = 'select * from user_sign_in($1, $2, $3, $4)' // SQLI
    client.query(sql, [session.session_id, device, auth_info, char_info])
        .then(result => {
            let user_token = result.rows[0].user_sign_in
            if (!user_token) done('user_token')
            done(null, session.redirect_url, user_token)
        })
        .catch(e => done(`user sign in: ${e}`))
}

module.exports.newSession = newSession;
module.exports.retrieveSession = retrieveSession;
module.exports.completeSession = completeSession;
