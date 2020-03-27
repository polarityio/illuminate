'use strict';

const request = require('request');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

let Logger;
let requestWithDefaults;

const MAX_PARALLEL_LOOKUPS = 10;

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function startup(logger) {
  let defaults = {};
  Logger = logger;

  const { cert, key, passphrase, ca, proxy, rejectUnauthorized } = config.request;

  if (typeof cert === 'string' && cert.length > 0) {
    defaults.cert = fs.readFileSync(cert);
  }

  if (typeof key === 'string' && key.length > 0) {
    defaults.key = fs.readFileSync(key);
  }

  if (typeof passphrase === 'string' && passphrase.length > 0) {
    defaults.passphrase = passphrase;
  }

  if (typeof ca === 'string' && ca.length > 0) {
    defaults.ca = fs.readFileSync(ca);
  }

  if (typeof proxy === 'string' && proxy.length > 0) {
    defaults.proxy = proxy;
  }

  if (typeof rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

function _convertPolarityTypeToIlluminateType(entity) {
  switch (entity.type) {
    case 'IPv4':
      return 'ip';
    case 'IPv6':
      return 'ipv6';
    case 'hash':
      return 'file';
    case 'email':
      return 'email';
    case 'domain':
      return 'domain';
  }
}

function getIndicatorMatchRequestOptions(entity, options) {
  const url = options.url.endsWith('/') ? options.url : `${options.url}/`;

  return {
    method: 'GET',
    uri: `${url}api/1_0/indicator/match`,
    qs: {
      value: entity.value,
      type: _convertPolarityTypeToIlluminateType(entity)
    },
    auth: {
      user: options.userName,
      pass: options.password
    },
    json: true
  };
}

function getSearchRequestOptions(entity, options) {
  const url = options.url.endsWith('/') ? options.url : `${options.url}/`;

  return {
    method: 'GET',
    uri: `${url}api/1_0/indicator`,
    qs: {
      searchTerm: entity.value
    },
    auth: {
      user: options.userName,
      pass: options.password
    },
    json: true
  };
}

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  Logger.debug({entities, options}, 'doLookup');

  entities.forEach((entity) => {
    let requestOptions = options.doIndicatorMatchSearch
      ? getIndicatorMatchRequestOptions(entity, options)
      : getSearchRequestOptions(entity, options);

    Logger.trace({ requestOptions }, 'Request Options');

    tasks.push(function(done) {
      requestWithDefaults(requestOptions, function(error, res, body) {
        Logger.trace({ body }, 'Body');
        let processedResult = handleRestError(error, entity, res, body);

        if (processedResult.error) {
          done(processedResult);
          return;
        }

        done(null, processedResult);
      });
    });
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      Logger.error({ err: err }, 'Error');
      cb(err);
      return;
    }

    results.forEach((result) => {
      if (result.body === null || _isMiss(result.body, options)) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        lookupResults.push({
          entity: result.entity,
          data: {
            summary: _getSummaryTags(result, options),
            details: Array.isArray(result.body.results) ? result.body : { totalResults: 1, results: [result.body] }
          }
        });
      }
    });

    Logger.debug({ lookupResults }, 'Results');
    cb(null, lookupResults);
  });
}

function _getSummaryTags(result, options) {
  const tags = [];

  if (options.doIndicatorMatchSearch) {
    tags.push(`TLP: ${result.body.tlp}`);
    tags.push(`Reports: ${result.body.reportCount}`);
  } else {
    tags.push(`Results: ${result.body.totalResults}`);
  }
  return tags;
}

const _isMiss = (body, options) => {
  let noValidReturnValues;
  if (options.doIndicatorMatchSearch) {
    // misses are handled vi a 404 return code so we don't need to check the payload
    noValidReturnValues = false;
  } else {
    noValidReturnValues = !(Array.isArray(body.results) && body.results.length > 0);
  }

  return !body || noValidReturnValues;
};

function handleRestError(error, entity, res, body) {
  let result;

  if (error) {
    return {
      error: error,
      detail: 'HTTP Request Error'
    };
  }
  if (res.statusCode === 200) {
    // we got data!
    result = {
      entity: entity,
      body: body
    };
  } else if (res.statusCode === 404) {
    // no result found
    result = {
      entity: entity,
      body: null
    };
  } else if (res.statusCode === 400) {
    result = {
      error: body,
      detail: '400 - Bad Request Parameters'
    };
  } else {
    // unexpected status code
    result = {
      error: body,
      detail: `Unexpected HTTP Status Code ${res.statusCode} received`
    };
  }
  return result;
}

module.exports = {
  doLookup: doLookup,
  startup: startup
};
