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

```
var WebmakerAuth = require('webmaker-auth');

var webmakerAuth = new WebmakerAuth({
  // required
  loginURL: process.env.LOGIN_URL,
  secretKey: process.env.SECRET_KEY,

  // optional
  domain: process.env.COOKIE_DOMAIN, // default undefined
  forceSSL: process.env.FORCE_SSL, // default false
  maxAge: process.env.MAX_AGE // default 365 days
});

app.post('/verify', webmakerAuth.handlers.verify);
app.post('/authenticate', webmakerAuth.handlers.authenticate);
app.post('/create', webmakerAuth.handlers.create);
app.post('/logout', webmakerAuth.handlers.logout);
app.post('/check-username', webmakerAuth.handlers.exists);


```

### TODO:

* tests
