[![Build Status](https://travis-ci.org/mozilla/webmaker-auth.png)](https://travis-ci.org/mozilla/webmaker-auth)

# Webmaker auth middleware

## Install

`npm install webmaker-auth`


## usage

```
var WebmakerAuth = require('webmaker-auth');

var webmakerAuth = new WebmakerAuth({
  loginURL: env.get('LOGIN_URL'),
  secretKey: env.get('SECRET_KEY')
});

app.post('/verify', webmakerAuth.handlers.verify);
app.post('/authenticate', webmakerAuth.handlers.authenticate);
app.post('/create', webmakerAuth.handlers.create);
app.post('/logout', webmakerAuth.handlers.logout);

```

### TODO:

* tests
