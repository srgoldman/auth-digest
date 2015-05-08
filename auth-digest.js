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
  onSuccess: A function to call with the responseText if the call succeeds
  onError:   A function to call with the request and event (null for synchronous calls)
  username:  The username to use for authentication
  password:  The password to user for authentication

  Returns: the xmlHttpRequest object

*/

exports.makeHttpCall = function (url, route, async, onSuccess, onError, username, password)
{
    return makeHttpCallInternal(url, route, async, onSuccess, onError, username, password, null);
};

function getHttpRequest(url, route, async, xhr, username, password) {
    console.log("getHttpRequest: " + (async ? "(async) " : "(sync) ") + url);

    var authHdr = buildAuthResponse(xhr, route, username, password);
    var req = new XMLHttpRequest();
    req.open('GET', url, async);

    if (authHdr.length) {
	//console.log("Setting Authorization: " + authHdr);
	req.setRequestHeader("Authorization", authHdr);
    }
    return req;
}

function makeHttpCallInternal(url, route, async, onSuccess, onError, username, password, xhrOrig)
{
    var xhr = getHttpRequest(url, route, async, xhrOrig, username, password);
    var processResults = function(e) {
	if (xhr.readyState != 4) return xhr;
	switch (xhr.status) {
	case 401:
	    if (xhrOrig === null)
		// This is the first failure, retry with proper header
		return makeHttpCallInternal(url, route, async, onSuccess, onError, username, password, xhr);
	    else
		console.log("We have repeated failures to authenticate. Please check your credentials.");
	    break;
	case 200:
	    if (onSuccess !== null) onSuccess(xhr.responseText);
	    break;
	default:
	    if (onError !== null) 
		onError(xhr, e);
	    else
		console.log("There was an error: " + JSON.stringify(xhr));
	}
	return xhr;
    };
    if (async) xhr.onreadystatechange = processResults;
    xhr.send();
    return async ? xhr : processResults(null);
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

function buildAuthResponse(xhr, uri, username, password) 
{
    if (xhr === null) return "";
    var challenge = xhr.getResponseHeader('WWW-Authenticate');
    if (challenge === null || challenge === undefined) return "";
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
