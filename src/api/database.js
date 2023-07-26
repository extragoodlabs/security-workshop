const { Sequelize } = require('sequelize');
const config = require('config');
const models = require('./models');

const dbConfig = config.get('database');
const sequelize = new Sequelize(dbConfig);

models(sequelize);

module.exports = sequelize;
