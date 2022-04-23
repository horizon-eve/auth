
const request = require('request')
const session = require('../src/session')
const proxyquire = require('proxyquire')

const URL_BASE = 'http://localhost:3001'
let server

const scenarios = [
  {title: 'Sign in user with sso character step 1', steps: [
      {method: 'POST', uri: '/login/user', headers: {"user-agent": "test"},
        body: {callback: "test_callback", verify: "123", scope: "test_scope"},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(302)
          expect(response.headers.location).toBe(
            "https://test_auth_url?response_type=code&redirect_uri=http%3A%2F%2Ftest_redirect_url&client_id=test_client_id&scope=test_scope&state=101")
        }},
    ]},
  {title: 'Sign in user with sso character - no callback', steps: [
      {method: 'POST', uri: '/login/user', headers: {"user-agent": "test"},
        body: {verify: "123", scope: "test_scope"},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("please specify referrer")
        }},
    ]},
  {title: 'Sign in user with sso character - no verify', steps: [
      {method: 'POST', uri: '/login/user', headers: {"user-agent": "test"},
        body: {callback: "test_callback", scope: "test_scope"},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("please specify verification token")
        }},
    ]},
  {title: 'Sign in user with sso character - no user agent', steps: [
      {method: 'POST', uri: '/login/user', headers: {},
        body: {callback: "test_callback", verify: "123", scope: "test_scope"},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("can not process this request")
        }},
    ]},
  {title: 'Refresh user token - token not valid', steps: [
      {
        method: 'PATCH', uri: '/login/user', headers: {"user-agent": "test", "x-hr-authtoken": "12345"}, body: {},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(404)
        }},
   ]},
  {title: 'Refresh user token - miss useragent', steps: [
      {
        method: 'PATCH', uri: '/login/user', headers: {"x-hr-authtoken": "12345"}, body: {},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("can not process this request")
        }},
    ]},
  {title: 'Link sso character to existing user - invalid auth', steps: [
      {
        method: 'POST', uri: '/login/user/characters', headers: {"user-agent": "test", "x-hr-authtoken": "12345"},
        body: {callback: "/test_callback", verify: "test_verify", scope: "test_scope"},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(401)
          expect(response.body.message).toBe("could not authenticate")
        }},
    ]},
  {title: 'Link sso character to existing user - miss user-agent', steps: [
      {
        method: 'POST', uri: '/login/user/characters', headers: {"x-hr-authtoken": "12345"},
        body: {callback: "/test_callback", verify: "test_verify", scope: "test_scope"},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("can not process this request")
        }},
    ]},
  {title: 'Link sso character to existing user - miss auth header', steps: [
      {
        method: 'POST', uri: '/login/user/characters', headers: {"user-agent": "test"},
        body: {callback: "/test_callback", verify: "test_verify", scope: "test_scope"},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("please specify auth_token")
        }},
    ]},
  {title: 'Link sso character to existing user - miss callback', steps: [
      {
        method: 'POST', uri: '/login/user/characters', headers: {"user-agent": "test", "x-hr-authtoken": "12345"},
        body: {verify: "test_verify", scope: "test_scope"},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("please specify referrer")
        }},
    ]},
  {title: 'Link sso character to existing user - callback is not relative path', steps: [
      {
        method: 'POST', uri: '/login/user/characters', headers: {"user-agent": "test", "x-hr-authtoken": "12345"},
        body: {callback: "test_callback", verify: "test_verify", scope: "test_scope"},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("please specify referrer")
        }},
    ]},
  {title: 'Link sso character to existing user - miss verify', steps: [
      {
        method: 'POST', uri: '/login/user/characters', headers: {"user-agent": "test", "x-hr-authtoken": "12345"},
        body: {callback: "/test_callback", scope: "test_scope"},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("please specify verification token")
        }},
    ]},
  {title: 'Refresh character authentication token - invalid auth', steps: [
      {
        method: 'PATCH', uri: '/login/user/characters/char123', headers: {"user-agent": "test", "x-hr-authtoken": "12345"}, body: {},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(401)
          expect(response.body.message).toBe("could not authenticate")
        }},
    ]},
  {title: 'Refresh character authentication token - miss user agent', steps: [
      {
        method: 'PATCH', uri: '/login/user/characters/char123', headers: {"x-hr-authtoken": "12345"}, body: {},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("can not process this request")
        }},
    ]},
  {title: 'Refresh character authentication token - miss auth token', steps: [
      {
        method: 'PATCH', uri: '/login/user/characters/char123', headers: {"user-agent": "test"}, body: {},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("please specify auth_token")
        }},
    ]},
  {title: 'Unlink character from the user - invalid auth', steps: [
      {
        method: 'DELETE', uri: '/login/user/characters/char123', headers: {"user-agent": "test", "x-hr-authtoken": "12345"}, body: {},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(401)
          expect(response.body.message).toBe("could not authenticate")
        }},
    ]},
  {title: 'Unlink character from the user - miss user agent', steps: [
      {
        method: 'DELETE', uri: '/login/user/characters/char123', headers: {"x-hr-authtoken": "12345"}, body: {},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("can not process this request")
        }},
    ]},
  {title: 'Unlink character from the user - miss auth header', steps: [
      {
        method: 'DELETE', uri: '/login/user/characters/char123', headers: {"user-agent": "test"}, body: {},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("please specify auth_token")
        }},
    ]},
  {title: 'SSO Callback - invalid state', steps: [
      {
        method: 'GET', uri: '/login/callback?state=123&code=12345', headers: {"user-agent": "test"}, body: {},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(404)
          expect(response.body.message).toBe("state")
        }},
    ]},
  {title: 'SSO Callback - miss state', steps: [
      {
        method: 'GET', uri: '/login/callback?code=12345', headers: {"user-agent": "test"}, body: {},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("please specify state")
        }},
    ]},
  {title: 'SSO Callback - miss code', steps: [
      {
        method: 'GET', uri: '/login/callback?state=123', headers: {"user-agent": "test"}, body: {},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("please specify code")
        }},
    ]},
  {title: 'SSO Callback - miss user agent', steps: [
      {
        method: 'GET', uri: '/login/callback?state=123&code=12345', headers: {}, body: {},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("can not process this request")
        }},
    ]},
  {title: 'Finish SSO flow and link character to user - invalid verify', steps: [
      {
        method: 'POST', uri: '/login/verify', headers: {"user-agent": "test"},
        body: {verify: "test_verify"},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(401)
          expect(response.body.message).toBe("No authorization to verify 'test_verify'")
        }},
    ]},
  {title: 'Finish SSO flow and link character to user - miss verify', steps: [
      {
        method: 'POST', uri: '/login/verify', headers: {"user-agent": "test"}, body: {},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("please specify client to verify")
        }},
    ]},
  {title: 'Finish SSO flow and link character to user - miss user agent', steps: [
      {
        method: 'POST', uri: '/login/verify', headers: {},
        body: {verify: "test_verify"},
        verify: function (error, response) {
          expect(error).toBeNull()
          expect(response.statusCode).toBe(400)
          expect(response.body.message).toBe("can not process this request")
        }},
    ]},
]

describe('Auth Routes', () => {

  beforeAll(() => {
    server = require('../src/www')
  })

  beforeEach(() => {
    session.reset()
  })

  scenarios.forEach(s => {
    test(s.title, (done) => {
      chainSteps(s.steps.entries(), done)
    })
  })

  afterAll(() => {
    if (server) {
      server.close()
    }
  })
})

function chainSteps(steps, done) {
  const nextStep = steps.next().value
  if (nextStep) {
    const step = nextStep[1]
    request({
        method: step.method,
        uri: URL_BASE + step.uri,
        headers: step.headers,
        body: step.body,
        json: true
      },
      function (error, response, body) {
        step.verify(error, response, body)
        chainSteps(steps, done)
      })
  } else {
    done()
  }
}
