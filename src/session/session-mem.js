

let id_gen = 1
let sessions = {}


function newSession(redirect_url, user_agent, verify, done) {
  let session_id = ++id_gen
  sessions[session_id] = {
    session_id: session_id,
    redirect_url: redirect_url,
    user_agent: user_agent,
    verify: verify
  }
  done(null, session_id)
}

function retrieveSession(session_id, done, next) {
  let session = sessions[session_id]
  if (!session)
    return done(`state ${session_id}`)
  next(session, done)
}

function updateSession(ss, data) {
  let session = sessions[ss.session_id]
  if (session) {
    Object.assign(session, data)
  }
}

function completeSession(verify, user_agent, done) {
  // TBD
  done(null, null)
}


module.exports.newSession = newSession;
module.exports.retrieveSession = retrieveSession;
module.exports.completeSession = completeSession;
module.exports.updateSession = updateSession;
