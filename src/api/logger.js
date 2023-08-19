const pino = require('pino');

// Create a logging instance
const logger = pino({
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
});

module.exports = logger;
