/*
  auth-digest.js
 
  Copyright (c) 2015, Seth Goldman
  All rights reserved.
 
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:
 
  1. Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
 
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 This is the only entry point.

  makeHttpCall will catch 401 (unauthorized) errors and retry the request with
  the proper authentication header for digest authentication.

  url:       This is the fully qualified path to the resource
  route:     This is the path without the domain
  async:     Run this request asynchronously? (true or false)
  callback:  A standard Node.js callback function (error, xhr)
  username:  The username to use for authentication
  password:  The password to user for authentication

  Returns: the xmlHttpRequest object

*/

exports.makeHttpCall = function (url, route, callback, username, password)
{
    return makeHttpCallInternal(url, route, callback, username, password, null, 0);
};

var authHdr = "";

function getHttpRequest(url, route, challenge, username, password) {
    console.log("getHttpRequest: " + url);

    authHdr = buildAuthResponse(challenge, route, username, password);
    var req = new XMLHttpRequest();
    req.open('GET', url, true);

    if (authHdr.length) {
	//console.log("Setting Authorization: " + authHdr);
	req.setRequestHeader("Authorization", authHdr);
    }
    return req;
}

function makeHttpCallInternal(url, route, callback, username, password, challenge, numRetries)
{
    var maxRetries = 1;
    var xhr = getHttpRequest(url, route, challenge, username, password);
    var processResults = function(e) {
	if (xhr.readyState != 4) return null;
	switch (xhr.status) {
	case 401:
	    if (challenge === null || numRetries < maxRetries) {
		// This is the first failure, retry with proper header
		challenge = xhr.getResponseHeader('WWW-Authenticate');
		if (url.indexOf("_method=put") > 0 || url.indexOf("_method=execute") > 0) {
		    // PUT requests end up redirecting (status 303) which we don't receive.
		    // On iOS, the authentication header gets lost so we end up here with a 401
		    // error and reexecute the PUT which is the wrong behavior.
		    // Strip down the request and retry.
		    url = url.split("?")[0];
		    route = route.split("?")[0];
		}
		return makeHttpCallInternal(url, route, callback, username, password, challenge, numRetries+1);
	    } else {
		console.log("We have repeated failures to authenticate. Please check your credentials.");
		if (callback !== null) callback(new Error(JSON.stringify(e)), xhr);
	    }
	    break;
	case 200:
	    if (callback !== null) callback(null, xhr.responseText);
	    break;
	default:
	    if (callback !== null) callback(new Error(e), xhr);
	    else console.log("There was an error: " + JSON.stringify(xhr));
	    break;
	}
    };
    xhr.onreadystatechange = processResults;
    xhr.send();
}

var md5 = require('crypto-js/md5');

function unquotes(val) { return val.replace(/^\"+|\"+$/gm, ''); }

function pad(num, size) 
{
    var s = num+"";
    while (s.length < size) s = "0" + s;
    return s;
}

function genNonce(len) {
    var text = "";
    var possible = "ABCDEF0123456789";
    for(var i=0; i<len; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}

var nc = 1;

function buildAuthResponse(challenge, uri, username, password) 
{
    if (challenge === null || challenge === undefined) return authHdr;
    var pos = challenge.indexOf(" ");
    var tokens = {cnonce: genNonce(16)};
    var pairs = challenge.substr(pos).trim().split(',');
    tokens.nc = pad(nc++, 8);

    for (var token in pairs) {
	//console.log(pairs[token].trim());
	var pair = pairs[token].trim().split('=');
	tokens[pair[0]] = pair[1];
    }

    var HA1 = md5(username + ":" + unquotes(tokens.realm) + ":" + password);
    var HA2 = md5("GET:" + uri);
    var response = md5(HA1 + ':' + 
		       unquotes(tokens.nonce) + ':' +
		       tokens.nc + ':' +
		       tokens.cnonce + ':' +
		       unquotes(tokens.qop) + ':' +
		       HA2);
    return buildAuthResponseHeader(username, uri, tokens, response);
}

function buildAuthResponseHeader(username, uri, tokens, response) {
    var header = "Digest " +
	'username="' + username + '"' +
	', realm=' + tokens.realm +
	', nonce=' + tokens.nonce +
	', uri="' + uri + '"' +
	//	', algorithm=' + tokens.algorithm +
	', response="' + response + '"' +
	', qop=' + unquotes(tokens.qop) +
	', nc=' + tokens.nc +
	', cnonce="' + tokens.cnonce + '"';
    return header;
}
