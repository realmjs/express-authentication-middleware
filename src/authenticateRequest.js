"use strict"

const jwt = require('jsonwebtoken');

const authenticateRequest = (secret) => () => (req, res, next) => {
  const bearerHeader = req.headers['authorization'];
  if (typeof bearerHeader === 'undefined') {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }
  const bearer = bearerHeader.split(" ");
  const token = bearer[1];
  res.locals.token = token;
  jwt.verify(token, secret, (err, decoded) => {
    if (err) {
      res.status(401).json({ message: 'Unauthorized' });
    } else {
      res.locals.uid = decoded.uid;
      next();
    }
  });
}

module.exports = authenticateRequest;
