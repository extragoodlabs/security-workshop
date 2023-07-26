const { DataTypes } = require('sequelize');

module.exports = (sequelize) => {
    const User = sequelize.define('user', {
        credit_card: {
            type: DataTypes.STRING(16),
            allowNull: false,
        },
        currency: {
            type: DataTypes.STRING(3),
            allowNull: false,
        },
        email: {
            type: DataTypes.TEXT,
            allowNull: false,
        },
        is_active: {
            type: DataTypes.BOOLEAN,
            defaultValue: true,
        },
        country: {
            type: DataTypes.STRING(3),
            allowNull: false,
        },
        num_logins: {
            type: DataTypes.INTEGER,
            defaultValue: 0,
        },
        password_hash: {
            type: DataTypes.STRING(32),
            allowNull: false,
        },
        username: {
            type: DataTypes.TEXT,
            allowNull: false,
        }
    }, {
        updatedAt: false,
        createdAt: 'created_at'
    });

    const Transaction = sequelize.define('transaction', {
        amount: {
            type: DataTypes.FLOAT,
            allowNull: false,
        },
        currency: {
            type: DataTypes.STRING(3),
            allowNull: false,
        },
        description: {
            type: DataTypes.TEXT,
            allowNull: false,
        },
        timestamp: {
            type: DataTypes.DATE,
            allowNull: false,
        },
    }, {
        timestamps: false,
    });

    User.hasMany(Transaction, { foreignKey: 'user_id' });
    Transaction.belongsTo(User, { foreignKey: 'user_id' });
};
