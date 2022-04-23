const { Pool } = require('pg')
const useragent = require('useragent')
const config = require('../config')
const {use} = require('express/lib/router')

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
    ready(client, release)
  })
}

function newSessionForUser(redirect_url, user_agent, verify, auth_token, done) {
  const device = get_device(user_agent)
  get_client((client, release) => {
    // Exchange auth token to user id
    client.query('SELECT * from auth.authenticate($1, $2, false)', [auth_token, device])
      .then(res => {
        const user_id = res.rows[0].authenticate
        if (!user_id) {
          release()
          return done({status: 401, message: 'could not authenticate'})
        } else {
          // start auth session for existing user_id
          const sql = 'insert into auth_session(redirect_url, user_agent, client_verify, user_id) values ($1, $2, $3, $4) returning session_id'
          client.query(sql, [redirect_url, user_agent, verify, user_id])
            .then(res => {
              done(null, res.rows[0].session_id)
            })
            .catch(e => done(`create session: ${e}`))
            .finally(() => release())
        }
      })
      .catch(e => {
        release()
        return done({status: 401, message: `create session: ${e}`})
      })
  })
}

function newSession(redirect_url, user_agent, verify, done) {
  // This is new session for a new user
  const sql = 'insert into auth_session(redirect_url, user_agent, client_verify) values ($1, $2, $3) returning session_id'
  get_client(function (client, release) {
    client.query(sql, [redirect_url, user_agent, verify])
      .then(res => {
        done(null, res.rows[0].session_id)
      })
      .catch(e => done(`create session: ${e}`))
      .finally(() => release())
  })
}

function retrieveSession(session_id, done, next) {
    const sql = 'select session_id, user_agent, redirect_url, auth_info, char_info, error, created, updated from auth_session where session_id = $1' // SQLI
    get_client(function (client, release) {
      client.query(sql, [session_id])
        .then(result => {
          let session = result.rows[0]
          if (!session)
            return done({status: 404, message: 'state'})
          next(session, done)
        })
        .catch(e => done(`get session: ${e}`))
        .finally(() => release())
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
    get_client(function (client, release) {
      client.query(sql, values)
        .catch(e => console.log(`error updating auth_session: ${e}`))
        .finally(() => release())
    })
}

function completeSession(verify, user_agent, done) {
    const device = get_device(user_agent)
    let sql = 'select * from user_sign_in($1, $2, $3)'
    get_client((client, release) => {
      client.query(sql, [verify, user_agent, device])
        .then(result => {
          done(null, result.rows[0].user_sign_in)
        })
        .catch(e => done(`user sign in: ${e}`))
        .finally(() => release())
    })
}

function unlinkCharacter(user_agent, auth_token, character_id, done) {
  const device = get_device(user_agent)
  get_client((client, release) => {
    client.query('SELECT * from auth.authenticate($1, $2, false)', [auth_token, device])
      .then(res => {
        const user_id = res.rows[0].authenticate
        if (!user_id) {
          release()
          return done({status: 401, message: 'could not authenticate'})
        } else {
          client.query('update auth.characters set user_id = null where character_id = $1 AND user_id = $2', [character_id, user_id])
            .then(() => done(null))
            .catch(e => done(`unlink character: ${e}`))
            .finally(() => release())
        }
      })
  })
}

function refreshUserToken(user_agent, auth_token, done) {
  const device = get_device(user_agent)
  get_client((client, release) => {
    client.query('select * from refresh_user_token($1, $2)', [auth_token, device])
      .then(res => done(null, res.rows[0].refresh_user_token))
      .catch(e => done(`refresh user token: ${e}`))
      .finally(() => release())
  })
}

function getExpiredRefreshToken(user_agent, auth_token, character_id, done, next) {
  const device = get_device(user_agent)
  get_client((client, release) => {
    client.query('SELECT * from auth.authenticate($1, $2, false)', [auth_token, device])
      .then(res => {
        const user_id = res.rows[0].authenticate
        if (!user_id) {
          release()
          return done({status: 401, message: 'could not authenticate'})
        } else {
          client.query('SELECT * from auth.get_character_token($1, $2)', [character_id, user_id])
            .then(() => {
              if (!res.rows[0].get_character_token) {
                return done({status: 401, message: 'could not authenticate'})
              }
              // Parse and check token
              const token = JSON.parse(res.rows[0].get_character_token)
              // make sure it is actually expired
              if (token.expires > new Date()) {
                return done({status: 400, message: 'not needed'})
              }
              next({character_id: character_id, character_token: token.character_token, client: client, release: release })
            })
            .catch(e => done(`get character token: ${e}`))
            .finally(() => release())
        }
      })
      .catch(e => {
        release()
        done(`get character token: ${e}`)
      })
  })
}

function insertCharacterToken(ctx, done) {
  const client = ctx.client
  const release = ctx.release
  const auth_info = ctx.auth_info
  const character_id = ctx.character_id
  client.query('SELECT * from auth.insert_character_token($1, $2, $3)', [character_id, null, auth_info])
    .then(() => done())
    .catch(e => done(`get character token: ${e}`))
    .finally(() => release())
}

function get_device(user_agent) {
    let ua =  useragent.parse(user_agent);
    return `${ua.family}-${ua.os.family}${ua.os.major}-${ua.device.family}`.toLowerCase()
}

module.exports.insertCharacterToken = insertCharacterToken
module.exports.unlinkCharacter = unlinkCharacter
module.exports.newSession = newSession
module.exports.newSessionForUser = newSessionForUser
module.exports.retrieveSession = retrieveSession
module.exports.completeSession = completeSession
module.exports.updateSession = updateSession
module.exports.refreshUserToken = refreshUserToken
module.exports.getExpiredRefreshToken = getExpiredRefreshToken
