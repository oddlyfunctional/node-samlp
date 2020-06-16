const { promisify } = require('util');

const {
  parseRequest,
  getSamlResponse,
  sendResponse,
  createResponse,
  sendError,
} = require('./samlp');

exports.parseRequest = promisify(parseRequest);
exports.getSamlResponse = promisify(getSamlResponse);
exports.createResponse = promisify(createResponse);
exports.sendResponse = promisify(sendResponse);
exports.sendError = promisify(sendError);
