/**
 * Created by eugenia on 17.12.16.
 */
const HTTP_STATUSES = require('http-statuses');
const Authenticator = require('./authenticator');

/**
 * Basic Authenticator.
 * @constructor
 * @param {object} options - Options. Optional
 * @param {boolean} options.passReqToCallback
 * @param {function} verify - Function for client credentials verification
 */

class BasicAuthenticator extends Authenticator {
  constructor(options, verify) {
    if (typeof options === 'function') {
      verify = options;
      options = {};
    }
    super({
      verify,
      name: Authenticator.AUTH_TYPE.BASIC
    });

    this.passReqToCallback = options.passReqToCallback;
  }

  /**
   * Authenticate
   * Extracts client credentials from Authorization header. Writes client model to req[options.userProperty]
   * @function
   * @param {object} req - incoming message
   */
  authenticate(req) {
    req = req.req || req;
    const { oauthifizerScope } = req;

    let auth = req.headers.authorization;
    if (!auth) {
      return oauthifizerScope.fail();
    }

    const parts = auth.split(' ');
    if (('basic' !== parts[0].toLowerCase()) || !parts[1]) {
      return oauthifizerScope.fail(HTTP_STATUSES.BAD_REQUEST, 'Invalid token provided');
    }

    auth = parts[1];

    auth = Buffer.from(auth, 'base64').toString();
    auth = auth.match(/^([^:]*):(.*)$/);
    if (!auth) {
      return oauthifizerScope.fail(HTTP_STATUSES.BAD_REQUEST, 'Invalid token provided');
    }

    function callback(err, user) {
      if (err) {
        return oauthifizerScope.error(err);
      }

      if (!user) {
        return oauthifizerScope.fail(
          HTTP_STATUSES.UNAUTHORIZED.code, HTTP_STATUSES.UNAUTHORIZED.message);
      }

      oauthifizerScope.logIn(user);
    }

    if (this.passReqToCallback) {
      return this.verify(req, auth[1], auth[2], callback.bind(this));
    } else {
      return this.verify(auth[1], auth[2], callback.bind(this));
    }
  }
}

module.exports = BasicAuthenticator;
