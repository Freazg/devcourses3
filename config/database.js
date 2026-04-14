const { Sequelize } = require('sequelize');

const sequelize = new Sequelize(
  'devcourses_db',
  'root',
  'password',   // замінити на свій пароль
  {
    host: 'localhost',
    dialect: 'mysql',
    logging: false,
  }
);

module.exports = sequelize;
