/**
 * Created by eugenia on 18.12.16.
 */

'use strict';

class Authenticator {
  constructor({ name, verify }) {
    if (!name) {
      throw new Error('Authenticator name must be provided!');
    }

    if (!verify) {
      throw new Error('Authenticator verification function must be provided');
    }

    this.name = name;
    this.verify = verify;
  }

  authenticate() {
    throw new Error('`authenticate` method must be overridden by subclass!');
  }
}

Authenticator.AUTH_TYPE = {
  BASIC: 'basic',
  BEARER: 'bearer',
  CLIENT: 'oauth2-client-password',
};

module.exports = Authenticator;
