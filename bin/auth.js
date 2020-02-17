const cfg = require('../bin/config')
    , session = require('../bin/session')
    , https = require('https')
    , request = require('request')


function startSession(referrer, useragent, done) {
    // tbd validate better
    if (!referrer) return done("please specify referrer")
    if (!useragent) return done("please specify user agent")

    session.newSession(referrer, useragent, done)
}

function continueAuthorization(state_id, code, done) {
    session.retrieveSession(state_id, done, function(state) {
        // Should not reuse existing session, let it start over
        if (state.auth_info || state.char_info || state.error) {
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
                    const err = `authres: ${authres}`
                    session.update(state, {error: err})
                    done(err)
                }
            })
        });
    authreq.on('error', function (error) {
        const err = `authreq: ${error}`
        session.update(state, {error: err})
        done(err)
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
                const err = `verify: ${error}`
                session.update(state, {error: err})
                done(err)

            }
            else{
                // Authentication Process succeeded
                session.completeSession(state, auth, JSON.parse(body), done)
            }
        });
}

function authHeader() {
    return 'Basic ' + Buffer.from(cfg.login.client_id + ':' + cfg.login.client_secret).toString('base64');
}

module.exports.continueAuthorization = continueAuthorization
module.exports.startSession = startSession
