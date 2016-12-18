/**
 * Created by eugenia on 18.12.16.
 */

class Authenticator {
  constructor ({name, verify}) {
    if (!name) {
      throw new Error('Authenticator name must be provided!');
    }

    if (!verify) {
      throw new Error('Authenticator verification function must be provided');
    }

    this.name = name;
    this.verify = verify;
  }

  static AUTH_TYPES = {
    BASIC: 'basic',
    BEARER: 'bearer',
    CLIENT: 'oauth-2-client-password'
  };

  authenticate () {
    throw new Error('`authenticate` method must be overridden by subclass!');
  }
}

module.exports = Authenticator;