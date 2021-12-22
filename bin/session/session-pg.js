const { Pool } = require('pg')
const useragent = require('useragent')
const fs = require("fs")
const config = require('../config')

const pool = new Pool({
  host: config.db.host,
  database: config.db.database,
  user: config.db.user,
  password: config.db.password,
  port: config.db.port,
  max: config.db.max_connections,
  idleTimeoutMillis: config.db.idle_timeout,
  connectionTimeoutMillis: config.db.connect_timeout
})

get_client(function (client) {
  client.query('SELECT NOW()', (err, result) => {
    client.release()
    if (err) {
      return console.error('Error executing query', err.stack)
    }
    console.log(result.rows)
  })
})

function get_client(ready) {
  pool.connect((err, client, release) => {
    if (err) {
      return console.error('Error acquiring client', err.stack)
    }
    ready(client)
  })
}

function newSession(redirect_url, user_agent, verify, done) {
    const sql = 'insert into auth_session(redirect_url, user_agent, client_verify) values ($1, $2, $3) returning session_id'
    get_client(function (client) {
      client.query(sql, [redirect_url, user_agent, verify])
        .then(res => {
          done(null, res.rows[0].session_id)
          client.release();
        })
        .catch(e => {
          done(`create session: ${e}`)
        })
    })
}

function retrieveSession(session_id, done, next) {
    const sql = 'select session_id, user_agent, redirect_url, auth_info, char_info, error, created, updated from auth_session where session_id = $1' // SQLI
    get_client(function (client) {
      client.query(sql, [session_id])
        .then(result => {
          let session = result.rows[0]
          client.release()
          if (!session)
            return done(`state ${session_id}`)
          next(session, done)
        })
        .catch(e => done(`get session: ${e}`))
    })
}

function updateSession(session, data) {
    data.updated = new Date()
    let fields = []
    let i = 0
    Object.keys(data).forEach(f => fields.push(`${f}=$${++i}`))
    const sql = `update auth_session set ${fields.join(', ')} where session_id = $${++i}`
    const values = Object.values(data)
    values.push(session.session_id)
    get_client(function (client) {
      client.query(sql, values)
        .then(res => {
          client.release()
        })
        .catch(e => console.log(`error updating auth_session: ${e}`))
    })
}

function completeSession(verify, user_agent, done) {
    const device = get_device(user_agent)
    let sql = 'select * from user_sign_in($1, $2, $3)'
    get_client(client => {
      client.query(sql, [verify, user_agent, device])
        .then(result => {
          done(null, result.rows[0].user_sign_in)
          client.release()
        })
        .catch(e => done(`user sign in: ${e}`))
    })
}

function get_device(user_agent) {
    let ua =  useragent.parse(user_agent);
    return `${ua.family}-${ua.os.family}${ua.os.major}-${ua.device.family}`.toLowerCase()
}

module.exports.newSession = newSession;
module.exports.retrieveSession = retrieveSession;
module.exports.completeSession = completeSession;
module.exports.updateSession = updateSession;

