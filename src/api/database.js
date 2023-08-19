const { Sequelize } = require('sequelize');
const config = require('config');
const models = require('./models');
const logger = require('./logger');

const dbConfig = config.get('database');
const sequelize = new Sequelize({ ...dbConfig, logging: sql => logger.info(sql) });

models(sequelize);

module.exports = sequelize;
