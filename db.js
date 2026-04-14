const { Sequelize } = require('sequelize');
require('dotenv').config();

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: 'postgres',
    dialectOptions: {
      ssl: {
        require: true,
        rejectUnauthorized: false
      }
    },
    logging: false
  }
);

// 🔥 Fake pool to keep your 1000-line code working
const pool = {
  query: async (sql, params = []) => {
    const [results] = await sequelize.query(sql, {
      replacements: params
    });
    return [results];
  },

  getConnection: async () => {
    const t = await sequelize.transaction();

    return {
      query: async (sql, params = []) => {
        const result = await sequelize.query(sql, {
          replacements: params,
          transaction: t
        });
        return result;
      },
      beginTransaction: async () => {},
      commit: async () => await t.commit(),
      rollback: async () => await t.rollback(),
      release: async () => {}
    };
  }
};

module.exports = pool;
