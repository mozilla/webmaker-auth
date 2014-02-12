var express = require('express');
var hyperquest = require('hyperquest');

module.exports = function(options) {

  options = options || {};

  var self = this;

  self.loginURL = options.loginURL || 'http://localhost:3000';

  self.maxAge = options.maxAge || 2678400000; // 31 days. Persona saves session data for 1 month
  self.forceSSL = options.forceSSL || false;
  self.secretKey = options.secretKey || 'BOBSYOURUNCLE';
  self.cookieName = options.cookieName || 'webmakerlogin.sid';

  // No user-defined login URL
  if (!options.loginURL) {
    console.error('WARNING (webmaker-loginapi): loginURL was not passed into configuration. Defaulting to http://localhost:3000');
  }

  self.cookieParser = function() {
    return express.cookieParser();
  };

  self.cookieSession = function() {
    return express.cookieSession({
      key: self.cookieName,
      secret: self.secretKey,
      cookie: {
        maxAge: self.maxAge,
        secure: self.forceSSL
      },
      proxy: true
    });
  };

  function authenticateCallback( err, req, res, json ) {
    if ( err ) {
      return res.json(500, {
        error: err
      });
    }
    if ( !json ) {
      return res.json(500, {
        error: 'The Login server sent an invalid response'
      });
    }
    if ( json.error ) {
      return res.json(200, {
        error: json.error
      });
    }
    if ( json.user ) {
      req.session.user = json.user;
      req.session.email = json.email;
      res.json(200, {
        user: json.user,
        email: json.email
      });
    } else {
      res.json(200, {
        error: 'No user for email address',
        email: json.email
      });
    }
  }

  self.handlers = {
    authenticate: function(req, res, next) {

      var hReq = hyperquest.post(self.loginURL + '/api/user/authenticate');
      hReq.on('error', next);
      hReq.on('response', function(resp) {
        if (resp.statusCode !== 200) {
          return res.json(500, {
            error: 'There was an error on the login server'
          });
        }

        var bodyParts = []
        var bytes = 0;
        resp.on('data', function (c) {
          bodyParts.push(c);
          bytes += c.length;
        });
        resp.on('end', function() {
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
      hReq.setHeader('Content-Type', 'application/json');
      hReq.end(JSON.stringify({
        assertion: req.body.assertion,
        audience: req.body.audience
      }), 'utf8');
    },
    verify: function(req, res) {
      if (!req.session.email && !req.session.user) {
        return res.send(200, {
          status: 'No Session'
        });
      }
      res.send(200, {
        status: 'Valid Session',
        user: req.session.user,
        email: req.session.email
      });
    },
    create: function(req, res, next) {
      var hReq = hyperquest.post(self.loginURL + '/api/user/create');
      hReq.on('error', next);
      hReq.on('response', function(resp) {
        if (resp.statusCode !== 200) {
          return res.json(500, {
            error: 'There was an error on the login server'
          });
        }

        var bodyParts = []
        var bytes = 0;
        resp.on('data', function (c) {
          bodyParts.push(c);
          bytes += c.length;
        });
        resp.on('end', function() {
          var body = Buffer.concat(bodyParts, bytes).toString('utf8');
          var json;

          try {
            json = JSON.parse(body);
          } catch (ex) {
            return res.json(500, {
              error: 'There was an error parsing the response from the Login Server'
            });
          }

          req.session.user = json.user;
          req.session.email = json.email;
          res.json(200, {
            user: json.user,
            email: json.email
          });
        });
      });
      hReq.setHeader('Content-Type', 'application/json');
      hReq.end(JSON.stringify({
        user: req.body.user
      }), 'utf8');
    },
    logout: function(req, res) {
      req.session = null;
      res.send();
    }
  };
};
