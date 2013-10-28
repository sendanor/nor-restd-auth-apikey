/* sysrestd-auth-apikey -- Basic Auth APIKEY authenticator */

var express = require('express');
var crypt = require('crypt3');
var HTTPError = require('nor-express').HTTPError;

function is_str(v) {
	return (typeof v === 'string') ? true : false;
}

function is_obj(v) {
	return (v && (typeof v === 'object')) ? true : false;
}

module.exports = function(opts) {
	opts = opts || {};
	var _keys = opts.keys || {};
	var _keys_exists = Object.prototype.hasOwnProperty.bind(_keys);
	function validate_apikey(apikey, secret) {
		if(!( is_str(apikey) && is_str(secret) )) {
			throw new TypeError("bad arguments");
		}
		if(!( _keys_exists(apikey) && is_obj(_keys[apikey]) )) {
			return false;
		}
		if(!( is_str(_keys[apikey].secret) && (_keys[apikey].secret.length >= 9) )) {
			throw new TypeError("bad internal storage");
		}
		return (crypt(secret, _keys[apikey].secret) === _keys[apikey].secret) ? true : false;
	}
	function handler(req, res, next) {
		express.basicAuth(validate_apikey)(req, res, function() {
			var apikey = req.user;
			var method = req.method;
			var access = is_obj(_keys[apikey].access) ? _keys[apikey].access : {};
			var access_exists = Object.prototype.hasOwnProperty.bind(access);
			if(access.read) {
				access.HEAD = true;
				access.GET = true;
			}
			if(access.write) {
				access.PUT = true;
				access.POST = true;
				access.DELETE = true;
			}
			if(! (access_exists(method) && (access[method] === true)) ) {
				throw new HTTPError(403, "Forbidden");
			}
			next();
		});
	};
	return handler;
};

/* EOF */
