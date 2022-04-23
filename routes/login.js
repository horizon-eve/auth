let express = require('express');
const config = require('../src/config');
const auth = require('../src/auth');
let router = express.Router();
let cors = require('cors')

/* Login Page. This is redundant route to showcase basic flow and should not be used in prod */
router.get('/', function(req, res, next) {
    res.render('login')
});

/**
 * This flow will sign in user with sso character
 */
router.post('/user', function(req, res) {
  const referrer = req.body.callback
  const useragent = req.headers['user-agent']
  const verify = req.body.verify
  const scope = req.body.scope
  auth.startSession(referrer, useragent, verify, (errors, state) => {
    handleStartSessionResponse(res, errors, state, scope)
  })
});

/**
 * This flow will refresh user token
 */
router.patch('/user', function(req, res) {
  const useragent = req.headers['user-agent']
  const auth_token = req.headers[config.server.auth_header]
  auth.refreshUserToken(useragent, auth_token, (errors, auth) => {
    handleAuthResponse(res, errors, auth)
  })
});

/**
 * This flow will link sso character to existing user
 */
router.post('/user/characters', function(req, res) {
  const referrer = req.body.callback
  const useragent = req.headers['user-agent']
  const verify = req.body.verify
  const auth_token = req.headers[config.server.auth_header]
  const scope = req.body.scope
  auth.startSessionForUser(referrer, useragent, verify, auth_token, (errors, state) => {
    handleStartSessionResponse(res, errors, state, scope)
  })
})

/**
 * Refresh character authentication token
 */
router.patch('/user/characters/:character_id', function(req, res) {
  const useragent = req.headers['user-agent']
  const auth_token = req.headers[config.server.auth_header]
  const character_id = req.params.character_id
  auth.refreshCharacterToken(useragent, auth_token, character_id, (errors) => {
    if (errors) {
      error_response(res, errors)
    } else {
      res.status(204).send()
    }
  })
});


/**
 * Unlink character from the user
 */
router.delete('/user/characters/:character_id', function(req, res) {
  const useragent = req.headers['user-agent']
  const auth_token = req.headers[config.server.auth_header]
  const character_id = req.params.character_id
  auth.unlinkCharacter(useragent, auth_token, character_id, (errors) => {
    if (errors) {
      error_response(res, errors)
    } else {
      res.status(204).send()
    }
  })
});

/**
 * SSO Callback
 */
router.get('/callback',
    function(req, res, next) {
        let state = req.query.state
        let code = req.query.code
        let useragent = req.headers['user-agent']
        auth.continueAuthorization(state, code, useragent, function(errors, redirect_url) {
            if (errors) {
              handleAuthResponse(res, errors, null)
            }
            else {
                res.redirect(redirect_url)
            }
        });
    }
);

/**
 * Finish SSO flow and link character to user
 * @type {{origin}}
 */
let corsVerify = { origin: config.verify.origin }
router.options('/verify', cors(corsVerify))

router.post('/verify', cors(corsVerify),
    function(req, res, next) {
        let verify = req.body.verify
        let useragent = req.headers['user-agent']
        auth.completeAuthorization(verify, useragent, (errors, auth) => {
          handleAuthResponse(res, errors, auth)
        })
    }
);

router.get('/error', function(req, res, next) {
  res.status(req.query.status)
  res.send(req.query.reason)
});


function handleStartSessionResponse(res, errors, state, scope) {
  if (errors) {
    error_response(res, errors)
  }
  else {
    res.redirect(config.login.authorization_url
      + '?response_type=' + encodeURIComponent(config.login.response_type)
      + '&redirect_uri=' + encodeURIComponent(config.login.redirect_uri)
      + '&client_id=' + encodeURIComponent(config.login.client_id)
      + '&scope=' + encodeURIComponent((scope ? scope: config.login.scope))
      + '&state=' + encodeURIComponent(state))
  }
}

function handleAuthResponse(res, errors, auth) {
  if (errors) {
    if (errors instanceof Error) {
      console.error("TODO: generate erorr id", errors)
    }
    error_response(res, errors)
  }
  else {
    res.setHeader('Content-Type', 'application/json');
    res.send(auth)
  }
}

function error_response (res, errors) {
  res.setHeader('Content-Type', 'application/json');
  res.status(errors.status ? errors.status : 500).send({
    message: errors.message ? errors.message : errors,
    status: errors.status ? errors.status : 500,
    timestamp: new Date()
  })
}

module.exports = router;
