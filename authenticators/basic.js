/**
 * Created by eugenia on 17.12.16.
 */
const HTTP_STATUSES = require('http-statuses');
const Authenticator = require('./authenticator');

class BasicAuthenticator extends Authenticator {
  constructor(options, verify) {
    if (typeof options === 'function') {
      verify = options;
      options = {};
    }

    this.passReqToCallback = options.passReqToCallback;

    super({
      verify,
      name: Authenticator.AUTH_TYPES.BASIC
    });
  }

  authenticate(req) {
    req = req.req || req;

    let auth = req.headers.authorization;
    if (!auth) {
      return this.fail();
    }

    const parts = auth.split(' ');
    if (('basic' !== parts[0].toLowerCase()) || !parts[1]) {
      return this.fail(HTTP_STATUSES.BAD_REQUEST, 'Invalid token provided');
    }

    auth = parts[1];

    auth = Buffer.from(auth, 'base64').toString();
    auth = auth.match(/^([^:]*):(.*)$/);
    if (!auth) {
      return this.fail(HTTP_STATUSES.BAD_REQUEST, 'Invalid token provided');
    }

    function callback(err, user) {
      if (err) {
        return this.error(err);
      }

      if (!user) {
        return this.fail(HTTP_STATUSES.UNAUTHORIZED.code, HTTP_STATUSES.UNAUTHORIZED.message);
      }

      this.logIn(user);
    }

    if (this.passReqToCallback) {
      return this.verify(req, auth[1], auth[2], callback.bind(this));
    } else {
      return this.verify(auth[1], auth[2], callback.bind(this));
    }
  }
}

module.exports = BasicAuthenticator;