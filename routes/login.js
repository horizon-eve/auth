let express = require('express');
const config = require('../bin/config');
const auth = require('../bin/auth');
let router = express.Router();
let cors = require('cors')

/* Login Page. */
router.get('/', function(req, res, next) {
    res.render('login')
});

router.post('/start', function(req, res) {
    let referrer = req.body.callback
    let useragent = req.headers['user-agent']
    let verify = req.body.verify
    auth.startSession(referrer, useragent, verify, function(errors, state) {
        if (errors) {
            res.statusCode = 400
            res.send(errors)
        }
        else {
            res.redirect(config.login.authorization_url
                + '?response_type=' + config.login.response_type
                + '&redirect_uri=' + config.login.redirect_uri
                + '&client_id=' + config.login.client_id
                + '&scope=' + config.login.scope
                + '&state=' + state)
        }
    })
});

router.get('/callback',
    function(req, res, next) {
        let state = req.query.state
        let code = req.query.code
        let useragent = req.headers['user-agent']
        auth.continueAuthorization(state, code, useragent, function(errors, redirect_url) {
            if (errors) {
                console.log("errors: " + errors)
                res.redirect('/error?' + 'status=400&reason=' + errors);
            }
            else {
                res.redirect(redirect_url)
            }
        });
    }
);

let corsVerify = { origin: config.verify.origin }
router.options('/verify', cors(corsVerify))

router.post('/verify', cors(corsVerify),
    function(req, res, next) {
        let verify = req.body.verify
        let useragent = req.headers['user-agent']
        auth.completeAuthorization(verify, useragent, function(errors, auth) {
            if (errors) {
              console.log("errors: " + errors)
              res.statusCode = 400
              res.send(errors)
            }
            else {
              console.log(`authorization verified: ${verify}`)
              res.setHeader('Content-Type', 'application/json');
              res.send(auth)
            }
        });
    }
);

router.get('/error', function(req, res, next) {
    res.status(req.query.status)
    res.send(req.query.reason)
});

module.exports = router;

