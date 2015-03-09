module.exports = (function() {
  "use strict";

  console.log("Using webmaker-auth in test mode.");

  var username = "testuser";
  var usermail = "test@example.org";
  var hash = "0c17bf66e649070167701d2d3cd71711";

  var basicuser = {
    username: username,
    email: usermail
  };

  var userdata = {
    user: {
      username: username,
      email: usermail,
      emailHash: hash,
      avatar: 'https://secure.gravatar.com/avatar/'+hash+'?d=https%3A%2F%2Fstuff.webmaker.org%2Favatars%2Fwebmaker-avatar-200x200.png',
      prefLocale: 'en-US',
      id: 1,
      isAdmin: false,
      isMentor: false,
      isSuperMentor: false,
      sendEventCreationEmails: true,
      sendCoorganizerNotificationEmails: true,
      sendMentorRequestEmails: true
    }
  };

  var okay = { status: "okay" };

  function authenticateCallback(req, res, json) {
    req.session.user = username;
    req.session.email = usermail;
    req.session.refreshAfter = Date.now() + 1000 * 60 * 15; // 15 minutes
    if(json) res.json(json);
    else res.json(basicuser);
  }

  function refreshSession(req, res) {
    return authenticateCallback(false, req, res, userdata);
  }

  return function(options) {
    var authLoginURL = options.authLoginURL;
    return {
      uidExists: function (req, res, next) {
       res.json({ exists: true, usePasswordLogin: true, verified: true });
      },
      verify: function (req, res) {
        if (!req.session.email && !req.session.user) {
          return res.json({
            status: 'No Session'
          });
        }

        if (authLoginURL && (!req.session.refreshAfter || req.session.refreshAfter < Date.now())) {
          return refreshSession(req, res, next);
        }

        var response = JSON.parse(JSON.stringify(userdata));
        response.status = "Valid Session";
        res.json(response);
      },
      logout: function (req, res) {
        req.session.email = req.session.user = req.session.refreshAfter = null;
        res.json(okay);
      },
      request: function (req, res, next)           { authenticateCallback(req, res); },
      authenticate: function (req, res, next)      { authenticateCallback(req, res, userdata); },
      authenticateToken: function (req, res, next) { authenticateCallback(req, res, userdata); },
      createUser: function (req, res, next)        { authenticateCallback(req, res, userdata); },
      verifyPassword: function (req, res, next)    { authenticateCallback(req, res, userdata); },
      requestResetCode: function (req, res, next)  { res.json(okay); },
      resetPassword: function (req, res, next)     { res.json(okay); },
      removePassword: function (req, res, next)    { res.json(okay); },
      enablePasswords: function (req, res, next)   { res.json(okay); }
    };
  };
}());
