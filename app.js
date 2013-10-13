/**
 * Module dependencies
 */

var stack = require('simple-stack-common');
var envs = require('envs');
var passport = require('passport');
var HerokuSSO = require('passport-heroku-sso').Strategy;
var ss = require('simple-secrets');
var bitfield = require('bitfield');
var SmD = require('smd');

var app = module.exports = stack({
  base: {
    host: 'x-orig-host',
    path: 'x-orig-path',
    port: 'x-orig-port',
    proto: 'x-orig-proto'
  }
});

var DASHBOARD_URL = envs('DASHBOARD_URL');

/**
 * Setup access token generator
 */

var sender = ss(new Buffer(envs('ACCESS_TOKEN_SECRET'), 'hex'));

envs('PROVIDERS', '').split(',').forEach(function(provider) {
  if (!provider) return;

  var strategy = new HerokuSSO({
    salt: envs(provider.toUpperCase() + '_SALT')
  }, function(req, id, email, app, navData, done) {
    // TODO verify that the resource exists
    // TODO verify that the email exists

    done(null, {
      id: id,
      email: email,
      app: app
    });
  });

  passport.use(provider, strategy);

  app.post('/' + provider,
    authenticate(provider),
    generateToken(provider),
    function(req, res) {
      res.redirect(DASHBOARD_URL + '/apps/' + req.profile.id + '?_access_token=' + req.accessToken);
    });
});

function authenticate(provider) {
  var redirectURL = envs('REDIRECT_URL');
  return function(req, res, next) {
    passport.authenticate(provider, function(err, profile, info) {
      if (err) return next(err);
      if (profile === false) return next(new Error(info.message));
      req.profile = profile
      next();
    })(req, res, next);
  };
}

var ttl = envs.int('TTL', 5);

function generateToken(provider) {
  return function(req, res, next) {
    var expires = SmD.from(Date.now() + (ttl + 0.7) * SmD.ms_per_unit);

    req.accessToken = sender.pack({
      r: req.profile.id,
      a: req.profile.app,
      e: expires,
      p: provider
    });
    next();
  };
}
