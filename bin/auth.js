const cfg = require('../bin/config')
    , session = require('../bin/session')
    , https = require('https')
    , request = require('request')


function startSession(referrer, useragent, verify, done) {
    // tbd validate better
    if (!referrer) return done("please specify referrer")
    if (!useragent) return done("can not process this request")
    if (!verify) return done("please specify verification token")

    session.newSession(referrer, useragent, verify, done)
}

function continueAuthorization(state_id, code, useragent, done) {
    session.retrieveSession(state_id, done, function(state) {
        // Should not reuse existing session, let it start over
        if (state.committed === '1' || state.auth_info || state.char_info || state.error || state.user_agent !== useragent) {
            return done('please start over authorization')
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

function refreshToken(done) {
    var data = "grant_type=" + cfg.login.refresh_grant_type + "&refresh_token=" + code
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
    if (!verify) return done("please specify client to verify")
    if (!useragent) return done("can not process this request")
    session.completeSession(verify, useragent, done)
}


function authHeader() {
    return 'Basic ' + Buffer.from(cfg.login.client_id + ':' + cfg.login.client_secret).toString('base64');
}

module.exports.continueAuthorization = continueAuthorization
module.exports.startSession = startSession
module.exports.completeAuthorization = completeAuthorization;
