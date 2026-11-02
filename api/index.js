const requestHandler = require('../server.js');

module.exports = async (req, res) => {
  return requestHandler(req, res);
};
