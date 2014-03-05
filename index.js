var express = require('express');
var hyperquest = require('hyperquest');

module.exports = function (options) {

  options = options || {};

  var self = this;

  // missing session secret
  if (!options.secretKey) {
    throw new Error('(webmaker-auth): secretKey was not passed into configuration');
  }

  // missing login URL
  if (!options.loginURL) {
    throw new Error('(webmaker-auth): loginURL was not passed into configuration.');
  }

  self.loginURL = options.loginURL;

  self.maxAge = options.maxAge || 31536000000; // 365 days
  self.forceSSL = options.forceSSL || false;
  self.secretKey = options.secretKey;
  self.domain = options.domain;
  self.cookieName = 'webmakerlogin';

  self.cookieParser = function () {
    return express.cookieParser();
  };

  self.cookieSession = function () {
    var options = {
      key: self.cookieName,
      secret: self.secretKey,
      cookie: {
        maxAge: self.maxAge,
        secure: self.forceSSL
      },
      proxy: true
    };

    if (self.domain) {
      options.cookie.domain = self.domain;
    }

    var cookieSessionMiddleware = express.cookieSession(options);

    // This is a work-around for cross-origin OPTIONS requests
    // See https://github.com/senchalabs/connect/issues/323
    return function (req, res, next) {
      if (req.method.toLowerCase() === 'options') {
        return next();
      } else {
        cookieSessionMiddleware(req, res, next);
      }
    };

  };

  function authenticateCallback(err, req, res, json) {
    if (err) {
      return res.json(500, {
        error: err
      });
    }
    if (!json) {
      return res.json(500, {
        error: 'The Login server sent an invalid response'
      });
    }
    if (json.error) {
      return res.json({
        error: json.error
      });
    }
    if (json.user) {
      req.session.user = json.user;
      req.session.email = json.email;
      res.json(json);
    } else {
      res.json({
        error: 'No user for email address',
        email: json.email
      });
    }
  }

  self.handlers = {
    authenticate: function (req, res, next) {
      var hReq = hyperquest.post({
        headers: {
          'Content-Type': 'application/json'
        },
        uri: self.loginURL + '/api/user/authenticate'
      });
      hReq.on('error', next);
      hReq.on('response', function (resp) {
        if (resp.statusCode !== 200) {
          return res.json(resp.statusCode || 500, {
            error: 'There was an error on the login server'
          });
        }

        var bodyParts = [];
        var bytes = 0;
        resp.on('data', function (c) {
          bodyParts.push(c);
          bytes += c.length;
        });
        resp.on('end', function () {
          var body = Buffer.concat(bodyParts, bytes).toString('utf8');
          var json;

          try {
            json = JSON.parse(body);
          } catch (ex) {
            return authenticateCallback(ex);
          }

          authenticateCallback(null, req, res, json);
        });
      });
      hReq.end(JSON.stringify({
        assertion: req.body.assertion,
        audience: req.body.audience
      }), 'utf8');
    },
    exists: function (req, res, next) {
      var hReq = hyperquest.post({
        headers: {
          'Content-Type': 'application/json'
        },
        uri: self.loginURL + '/api/user/exists'
      });
      hReq.on('error', next);
      hReq.pipe(res);
      hReq.end(JSON.stringify(req.body), 'utf8');
    },
    verify: function (req, res) {
      if (!req.session.email && !req.session.user) {
        return res.send({
          status: 'No Session'
        });
      }
      res.send({
        status: 'Valid Session',
        user: req.session.user,
        email: req.session.email
      });
    },
    create: function (req, res, next) {
      var hReq = hyperquest.post({
        headers: {
          'Content-Type': 'application/json'
        },
        uri: self.loginURL + '/api/user/create'
      });
      hReq.on('error', next);
      hReq.on('response', function (resp) {
        if (resp.statusCode !== 200) {
          return res.json(resp.statusCode || 500, {
            error: 'There was an error on the login server'
          });
        }

        var bodyParts = [];
        var bytes = 0;
        resp.on('data', function (c) {
          bodyParts.push(c);
          bytes += c.length;
        });
        resp.on('end', function () {
          var body = Buffer.concat(bodyParts, bytes).toString('utf8');
          var json;

          try {
            json = JSON.parse(body);
          } catch (ex) {
            return res.json(500, {
              error: 'There was an error parsing the response from the Login Server'
            });
          }

          if (!json.user) {
            return res.json(500, {
              error: 'Error creating an account on ' + self.loginURL + ' - \"' + json.error + '\"'
            });
          }

          req.session.user = json.user;
          req.session.email = json.email;
          res.json(json);
        });
      });

      hReq.end(JSON.stringify({
        assertion: req.body.assertion,
        audience: req.body.audience,
        user: req.body.user
      }), 'utf8');
    },
    logout: function (req, res) {
      req.session.email = req.session.user = null;
      res.json({
        status: 'okay'
      });
    }
  };

  self.bind = function (app) {
    app.post('/verify', self.handlers.verify);
    app.post('/authenticate', self.handlers.authenticate);
    app.post('/create', self.handlers.create);
    app.post('/logout', self.handlers.logout);
    app.post('/check-username', self.handlers.exists);
  };
};
