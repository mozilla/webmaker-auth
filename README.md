[![Build Status](https://travis-ci.org/mozilla/webmaker-auth.png)](https://travis-ci.org/mozilla/webmaker-auth)

# Webmaker auth middleware

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
app.post('/check-username', self.handlers.exists);

// Shorthand to above
webmakerAuth.bind(app);

```

### TODO:

* tests
