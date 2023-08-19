const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const sequelize = require('./database');
const loggerMiddleware = require('pino-http');
const logger = require('./logger');

const indexRouter = require('./routes/index');
const usersRouter = require('./routes/users');
const transactionsRouter = require('./routes/transactions');

sequelize
    .authenticate()
    .then(() => {
        logger.info('Connection has been established successfully.');
    })
    .catch(err => {
        logger.error('Unable to connect to the database: %s', err);
        process.exit();
    });

const app = express();
app.use(loggerMiddleware({ logger }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.set('query parser', 'simple');
app.use(cookieParser());

app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/transactions', transactionsRouter);

logger.info('Application started!');

module.exports = app;
