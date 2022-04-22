const cfg = require('.//config')
    , session = require('./session')
    , https = require('https')
    , request = require('request')


function startSession(referrer, useragent, verify, done) {
    // tbd validate better
    if (!referrer) return done({status: 400, message: "please specify referrer"})
    if (!useragent) return done({status: 400, message: "can not process this request"})
    if (!verify) return done({status: 400, message: "please specify verification token"})

    session.newSession(referrer, useragent, verify, done)
}

function startSessionForUser(referrer, useragent, verify, auth_token, done) {
    // tbd validate better
    if (!referrer || !referrer.startsWith('/')) return done({status: 400, message: "please specify referrer"})
    if (!useragent) return done({status: 400, message: "can not process this request"})
    if (!verify) return done({status: 400, message: "please specify verification token"})
    if (!auth_token) return done({status: 400, message: "please specify auth_token"})

    session.newSessionForUser(referrer, useragent, verify, auth_token, done)
}

function unlinkCharacter(useragent, auth_token, character_id, done) {
    if (!useragent) return done({status: 400, message: "can not process this request"})
    if (!auth_token) return done({status: 400, message: "please specify auth_token"})
    if (!character_id) return done({status: 400, message: "please specify character_id"})

    session.unlinkCharacter(useragent, auth_token, character_id, done)
}

function refreshUserToken(useragent, auth_token, done) {
    if (!useragent) return done({status: 400, message: "can not process this request"})
    if (!auth_token) return done({status: 400, message: "please specify auth_token"})

    session.refreshUserToken(useragent, auth_token, done)
}

function continueAuthorization(state_id, code, useragent, done) {
    session.retrieveSession(state_id, done, function(state) {
        // Should not reuse existing session, let it start over
        if (state.committed === '1' || state.auth_info || state.char_info || state.error || state.user_agent !== useragent) {
            return done({status: 400, message: 'please start over authorization'})
        }
        exchangeAuthorizationCode(state, code, done)
    })
}

function exchangeAuthorizationCode(state, code, done) {
    var data = "grant_type=" + cfg.login.grant_type + "&code=" + code
    var authreq = https.request(
        {
            method: 'POST',
            hostname: cfg.login.token_host,
            port: 443,
            path: cfg.login.token_path,
            headers: {
                'Authorization': authHeader(),
                'Content-Type': 'application/x-www-form-urlencoded',
                'Host': cfg.login.token_host
            }
        },
        function (authres) {
            authres.on('data', function (d) {
                if (authres.statusCode == 200) {
                    // Obtain character information by access token
                    obtainCharacterInfo(state, JSON.parse(d), done)
                }
                else {
                    const errors = `authres: ${authres}`
                    session.updateSession(state, {error: errors})
                    done(errors)
                }
            })
        });
    authreq.on('error', function (error) {
        const errors = `authreq: ${error}`
        session.updateSession(state, {error: errors})
        done(errors)
    })
    authreq.write(data)
    authreq.end()
}

function refreshCharacterToken(useragent, auth_token, character_id, done) {
    if (!useragent) return done({status: 400, message: "can not process this request"})
    if (!auth_token) return done({status: 400, message: "please specify auth_token"})
    if (!character_id) return done({status: 400, message: "please specify character_id"})

    session.getExpiredRefreshToken(useragent, auth_token, character_id, done, (ctx) => {
        const query = "grant_type=" + cfg.login.refresh_grant_type + "&refresh_token=" + ctx.character_token
        const authreq = https.request(
          {
              method: 'POST',
              hostname: cfg.login.token_host,
              port: 443,
              path: cfg.login.token_path,
              headers: {
                  'Authorization': authHeader(),
                  'Content-Type': 'application/x-www-form-urlencoded',
                  'Host': cfg.login.token_host
              }
          },
          function (authres) {
              authres.on('data', function (auth_string) {
                  if (authres.statusCode == 200 && auth_string) {
                      ctx.auth_info = JSON.parse(auth_string)
                      session.insertCharacterToken(ctx, done)
                  }
                  else {
                      const errors = `authres: ${authres}`
                      done(errors)
                  }
              })
          });
        authreq.on('error', function (error) {
            const errors = `authreq: ${error}`
            done(errors)
        })
        authreq.write(query)
        authreq.end()
    })
}

function obtainCharacterInfo(state, auth, done) {
    request(
        {
            url : cfg.login.verification_url,
            headers : { "Authorization" : auth.token_type + ' ' + auth.access_token }
        },
        function (error, response, body) {
            if(error){
                const errors = `verify: ${error}`
                session.updateSession(state, {error: errors})
                done(errors)
            }
            else{
                // Authentication Process succeeded
                session.updateSession(state, {auth_info: auth, char_info: JSON.parse(body)})
                done(null, state.redirect_url)
            }
        });
}

function completeAuthorization(verify, useragent, done) {
    if (!verify) return done({status: 400, message: "please specify client to verify"})
    if (!useragent) return done({status: 400, message: "can not process this request"})
    session.completeSession(verify, useragent, done)
}


function authHeader() {
    return 'Basic ' + Buffer.from(cfg.login.client_id + ':' + cfg.login.client_secret).toString('base64');
}

module.exports.continueAuthorization = continueAuthorization
module.exports.startSession = startSession
module.exports.startSessionForUser = startSessionForUser
module.exports.completeAuthorization = completeAuthorization
module.exports.unlinkCharacter = unlinkCharacter
module.exports.refreshUserToken = refreshUserToken
module.exports.refreshCharacterToken = refreshCharacterToken
