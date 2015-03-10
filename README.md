[![Build Status](https://travis-ci.org/mozilla/webmaker-auth.png)](https://travis-ci.org/mozilla/webmaker-auth)

# Webmaker auth middleware

## Configure Webmaker login

You must configure your instance of the [Webmaker login server](https://github.com/mozilla/login.webmaker.org) to allow the domain on which your app is running.

For example, if your app is running on `http://localhost:7777`, you should add the following to the Webmaker login server's .env:

```
ALLOWED_DOMAINS="http://localhost:7777"
```

Alternatively, you can just set `ALLOWED_DOMAINS="*"` to make your life easier.

## Install

`npm install webmaker-auth`


## usage

```javascript
var WebmakerAuth = require('webmaker-auth');

// For Express 4 only
// var bodyParser = require('body-parser');

// Init
var webmakerAuth = new WebmakerAuth({
  // required
  loginURL: process.env.LOGIN_URL,
  authLoginURL: process.env.LOGIN_URL_WITH_AUTH,
  secretKey: process.env.SECRET_KEY,

  // This should be an array of URLs, or undefined.
  // If you pass in ["*"], all CORS domains will be allowed (don't do this on production)
  allowCors: ["*"],

  // The address to use when requesting a login link for a user - usually the hostname of the app.
  loginHost: process.env.LOGIN_HOST_ADDRESS

  // optional
  domain: process.env.COOKIE_DOMAIN, // default undefined
  forceSSL: process.env.FORCE_SSL // default false

  // if a cookie is older than the given time (in milliseconds), refresh the userdata
  refreshTime: 1000 * 60 * 5 // default 15 minutes,

  // optional - if set to 'true', webmaker-auth will bypass true login and simply treat any attempt
  // to log in as successful, yielding a session for user "testuser" with email "test@example.org"
  testMode: false
});

// Middleware
app.use(express.json());
app.use(express.urlencoded());

// For Express 4 use these includes instead of the previous 2
// app.use(bodyParser.json());
// app.use(bodyParser.urlencoded());

app.use(webmakerAuth.cookieParser());
app.use(webmakerAuth.cookieSession());

// Routes for front end
app.post('/auth/v2/verify', webmakerAuth.handlers.verify);
app.post('/auth/v2/authenticate', webmakerAuth.handlers.authenticate);
app.post('/auth/v2/logout', webmakerAuth.handlers.logout);
app.post('/auth/v2/create', webmakerAuth.handlers.createUser);
app.post('/auth/v2/uid-exists', webmakerAuth.handlers.uidExists);
app.post('/auth/v2/request', webmakerAuth.handlers.request);
app.post('/auth/v2/authenticateToken', webmakerAuth.handlers.authenticateToken);
app.post('/auth/v2/verify-password', webmakerAuth.handlers.verifyPassword);
app.post('/auth/v2/request-reset-code', webmakerAuth.handlers.requestResetCode);
app.post('/auth/v2/reset-password', webmakerAuth.handlers.resetPassword);

// These webmaker-auth route handlers require a csrf token and a valid user session.
app.post('/auth/v2/remove-password', webmakerAuth.handlers.removePassword);
app.post('/auth/v2/enable-passwords', webmakerAuth.handlers.enablePasswords);
```

### TODO:

* tests
