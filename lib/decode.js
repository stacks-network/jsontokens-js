'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.decodeToken = decodeToken;

var _base64url = require('base64url');

var _base64url2 = _interopRequireDefault(_base64url);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function decodeToken(token) {
    // decompose the token into parts
    var tokenParts = token.split('.');
    var header = JSON.parse(_base64url2.default.decode(tokenParts[0]));
    var payload = JSON.parse(_base64url2.default.decode(tokenParts[1]));
    var signature = tokenParts[2];

    // return the token object
    return {
        header: header,
        payload: payload,
        signature: signature
    };
}