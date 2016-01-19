/**
 * Copyright 2013-present NightWorld.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var util = require('util'),
    error = require('./error'),
    GrantBase = require('./grantBase');

module.exports = PreApprovedGrant;

// Runner that allows return values.
function runner (fns, context, next) {
  var last = fns.length - 1;

  (function run(pos) {
    fns[pos].call(context, function (err, response) {
      if (err) return next(err);
      if (pos === last) return next(null, response);
      run(++pos);
    });
  })(0);
}


/**
 * Constructor for a pre-approved Grant (allows direct grants of preApproved (sso) users).
 * In-server use only.
 *
 * @param {Object}   config         Instance of OAuth object
 * @param {Object}   preApproved    An Object containing user, client_id, and client_secret properties
 *                                  and optionally a grant_type property
 * @param {Function} next           ending callback.  passed (err, response)
 */
function PreApprovedGrant(config, preApproved, next) {
  GrantBase.call(this, config);
  this.preApproved = preApproved;
  this.grantType = preApproved.grant_type || 'preApproved';

  /**
   * This is the function order used by the runner
   *
   * @type {Array}
   */
  var fns = [ extractPreApprovedCredentials,
              this.checkClient,
              checkGrantType,
              this.generateAccessToken,
              this.saveAccessToken,
              this.generateRefreshToken,
              this.saveRefreshToken,
              returnPreApprovedResponse
            ];

  runner(fns, this, next);
}

util.inherits(PreApprovedGrant, GrantBase);

/**
 * Client Object (internal use only)
 *
 * @param {String} id     client_id
 * @param {String} secret client_secret
 */
function Client (id, secret) {
  this.clientId = id;
  this.clientSecret = secret;
}

function extractPreApprovedCredentials (done) {
  if (!this.preApproved.user) {
    return done(error('invalid_grant', 'Pre-approved user is missing'));
  }

  this.client = new Client(this.preApproved.client_id, this.preApproved.client_secret);
  // XX: share this block.
  if (!this.client.clientId ||
      !this.client.clientId.match(this.config.regex.clientId)) {
    return done(error('invalid_client',
                      'Invalid or missing client_id parameter'));
  } else if (!this.client.clientSecret) {
    return done(error('invalid_client', 'Missing client_secret parameter'));
  }

  done();
}

/**
 * Delegate to the relvant grant function based on grant_type
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkGrantType (done) {
  return usePreApprovedGrant.call(this, done);
}

/**
 * Grant for pre-approved grant type
 *
 * @param  {Function} done
 */
function usePreApprovedGrant (done) {
  this.user = this.preApproved.user;
  done();
}

/**
 * Return the response to the runner response
 *
 * @param  {Function} done
 * @this   OAuth
 */
function returnPreApprovedResponse (done) {
  var response = {
    token_type: 'bearer',
    access_token: this.accessToken
  };

  if (this.config.accessTokenLifetime !== null) {
    if (this.config.accessTokenLifetime[this.client.clientId] !== undefined) {
      // Allow custom lifetime per client
      response.expires_in = this.config.accessTokenLifetime[this.client.clientId];
    } else {
      response.expires_in = this.config.accessTokenLifetime;
    }
  }

  if (this.refreshToken) response.refresh_token = this.refreshToken;
  done(null, response);
}
