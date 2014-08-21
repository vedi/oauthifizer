var util = require('util');
var Q = require('q');
var oauth2orize = require('oauth2orize');
var passport = require('passport');

var BasicStrategy = require('passport-http').BasicStrategy;
var ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;
var BearerStrategy = require('passport-http-bearer').Strategy;

function OAuth2(authDelegate) {
  passport.use(new BasicStrategy(
    function (login, password, done) {
      Q.denodeify(authDelegate.findUserByLoginAndPassword.bind(authDelegate))(login, password)
        .nodeify(done)
      ;
    }
  ));

  passport.use(new ClientPasswordStrategy(
    function (clientId, clientSecret, done) {
      Q.denodeify(authDelegate.findClientByIdAndSecret.bind(authDelegate))(clientId, clientSecret)
        .nodeify(done)
      ;
    }
  ));

  passport.use(new BearerStrategy(
    function (accessToken, done) {
      Q.denodeify(authDelegate.findUserByAccessToken.bind(authDelegate))(accessToken)
        .then(function (result) {
          return done(null, result.obj, result.info)
        })
        .catch(function (err) {
          return done(err);
        })
      ;
    }
  ));


// create OAuth 2.0 server
  this.server = oauth2orize.createServer();

// Exchange login & password for access token.

  this.server.exchange(oauth2orize.exchange.password(function (client, login, password, scope, done) {
    var tokenValue;
    var refreshTokenValue;
    var user;

    Q.denodeify(authDelegate.findUserByLoginAndPassword.bind(authDelegate))(login, password)
      .then(function (result) {
        if (result === false) {
          throw false;
        }
        user = result;
        return Q.denodeify(authDelegate.cleanUpTokensByUserAndClient.bind(authDelegate))(user, client);
      })
      .then(function () {
        tokenValue = authDelegate.generateTokenValue();
        refreshTokenValue = authDelegate.generateTokenValue();
        return Q.denodeify(authDelegate.createTokensByUserAndClient.bind(authDelegate))(user, client, scope, tokenValue, refreshTokenValue)
      })
      .then(function () {
        return done(null, tokenValue, refreshTokenValue, authDelegate.getTokenInfo());
      })
      .catch(function (err) {
        if (err === false) {
          return done(null, false);
        } else {
          return done(err);
        }
      })
    ;
  }));

// Exchange refreshToken for access token.
  this.server.exchange(oauth2orize.exchange.refreshToken(function (client, refreshToken, scope, done) {
    var tokenValue;
    var refreshTokenValue;
    var user;

    Q.denodeify(authDelegate.findUserByRefreshToken.bind(authDelegate))(refreshToken)
      .then(function (result) {
        if (result.obj === false) {
          throw false;
        }
        user = result.obj;
        return Q.denodeify(authDelegate.cleanUpTokensByUserAndClient.bind(authDelegate))(user, client);
      })
      .then(function () {
        tokenValue = authDelegate.generateTokenValue();
        refreshTokenValue = authDelegate.generateTokenValue();
        return Q.denodeify(authDelegate.createTokensByUserAndClient.bind(authDelegate))(user, client, scope, tokenValue, refreshTokenValue)
      })
      .then(function () {
        return done(null, tokenValue, refreshTokenValue, authDelegate.getTokenInfo());
      })
      .catch(function (err) {
        if (err === false) {
          return done(null, false);
        } else {
          return done(err);
        }
      })
    ;
  }));
}

util.inherits(OAuth2, Object);


// token endpoint
//
// `token` middleware handles client requests to exchange authorization grants
// for access tokens.  Based on the grant type being exchanged, the above
// exchange middleware will be invoked to handle the request.  Clients must
// authenticate when making requests to this endpoint.

OAuth2.prototype.getToken = function() {
  return [
    passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
    this.server.token(),
    this.server.errorHandler()
  ];
};

OAuth2.passport = passport;

module.exports = OAuth2;

