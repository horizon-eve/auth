
let session_id_gen = 100
let user_token_id_gen = 1000
let user_id_gen = 10000
let sessions = {}
let users = {}
reset()

function reset() {
  session_id_gen = 100
  user_token_id_gen = 1000
  sessions = {}
  users = {}
}

function newSession(redirect_url, user_agent, verify, done) {
  let session_id = ++session_id_gen
  sessions[session_id] = {
    session_id: session_id,
    redirect_url: redirect_url,
    user_agent: user_agent,
    verify: verify,
    committed: 0
  }
  done(null, session_id)
}

function newSessionForUser(redirect_url, user_agent, verify, auth_token, done) {
  let session_id = ++session_id_gen
  let user = users[auth_token]
  if (!user)
    return done({status: 401, message: 'could not authenticate'})

  sessions[session_id] = {
    session_id: session_id,
    redirect_url: redirect_url,
    user_agent: user_agent,
    verify: verify,
    user_id: user.user_id,
    committed: 0
  }
  return done(null, session_id)
}

function retrieveSession(session_id, done, next) {
  let session = sessions[session_id]
  if (!session)
    return done({status: 404, message: 'state'})
  next(session, done)
}

function updateSession(ss, data) {
  let session = sessions[ss.session_id]
  if (session) {
    Object.assign(session, data)
  }
}

function refreshUserToken(useragent, auth_token, done) {
  const user = users[auth_token]
  if (!user) {
    done({status: 404})
  }
}

function unlinkCharacter(user_agent, auth_token, character_id, done) {
  const user = users[auth_token]
  if (!user) {
    return done({status: 401, message: 'could not authenticate'})
  }
}

function completeSession(verify, user_agent, done) {
  const session = Object.values(sessions).find(s => s.verify === verify && s.committed === 0)
  if (!session) {
    return done({status: 401, message: `No authorization to verify '${verify}'`})
  }
  const user_id = ++user_id_gen
  users[user_id] = {} // TODO: add something for the user
  done(null, user_id)
}

function getExpiredRefreshToken(user_agent, auth_token, character_id, done, next) {
  const user = users[auth_token]
  if (!user) {
    return done({status: 401, message: 'could not authenticate'})
  }
}

//module.exports.insertCharacterToken = insertCharacterToken
module.exports.unlinkCharacter = unlinkCharacter
module.exports.newSession = newSession
module.exports.newSessionForUser = newSessionForUser
module.exports.retrieveSession = retrieveSession
module.exports.completeSession = completeSession
module.exports.updateSession = updateSession
module.exports.refreshUserToken = refreshUserToken
module.exports.reset = reset
module.exports.getExpiredRefreshToken = getExpiredRefreshToken
