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

  // required --------------------
  // The location of the login server
  loginURL: 'http://localhost:3000',

  // The address to use when requesting a login link for a user - probably the host of the app
  // on which this is installed
  loginHost: 'http://myserver.webmaker.org'

  // This should match the secret key on login
  secretKey: 'BOB LOVES SOCKS',

  // optional --------------------

  // Fully qualified login API access point, if you need it
  authLoginURL: 'http://testuser:password@localhost:3000',

  // If you want to allow CORS requests on this server, use this option
  // This should be one of:
  //     ["*"] (allows all CORS domains. NOT FOR PRODUCTION)
  //     an array of URLs (e.g. ["http://whatever.org", "http://blah.org"])
  //     undefined
  allowCors: ["*"],

  // This is to support super cookie domains
  domain: 'webmaker.org', // default undefined

  forceSSL: true, // default false

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

## Migrating from 0.x.x

Note that the following handlers no longer exist and should be removed:

* webmakerAuth.handlers.create
* webmakerAUth.handlers.exists

### TODO:

* tests
