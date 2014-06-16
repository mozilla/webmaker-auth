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

  // The address to use when requesting a login link for a user - usually the hostname of the app.
  loginHost: process.env.LOGIN_HOST_ADDRESS

  // optional
  domain: process.env.COOKIE_DOMAIN, // default undefined
  forceSSL: process.env.FORCE_SSL // default false

  // if a cookie is older than the given time (in milliseconds), refresh the userdata
  refreshTime: 1000 * 60 * 5 // default 15 minutes
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
app.post('/verify', webmakerAuth.handlers.verify);
app.post('/authenticate', webmakerAuth.handlers.authenticate);
app.post('/create', webmakerAuth.handlers.create);
app.post('/logout', webmakerAuth.handlers.logout);
app.post('/check-username', webmakerAuth.handlers.exists);
```

### TODO:

* tests
