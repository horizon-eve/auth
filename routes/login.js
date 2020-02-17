var express = require('express');
const config = require('../bin/config');
const auth = require('../bin/auth');
var router = express.Router();

/* Login Page. */
router.get('/', function(req, res, next) {
    res.render('login')
});

router.get('/start', function(req, res) {
    let referrer = req.query.referrer ? req.query.referrer: req.headers.referer
    let useragent = req.headers['user-agent']
    auth.startSession(referrer, useragent, function(errors, state) {
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
        auth.continueAuthorization(state, code, function(errors, redirect_url, token) {
            if (errors) {
                console.log("errors: " + errors)
                res.redirect('/error?' + 'status=400&reason=' + errors);
            }
            else {
                res.cookie("hrsession", token, { maxAge: 900000})
                res.redirect(redirect_url)
            }
        });
    }
);

router.get('/error', function(req, res, next) {
    res.status(req.query.status)
    res.send(req.query.reason)
});

module.exports = router;

