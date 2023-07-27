CREATE TABLE users (
       id               INT PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
       created_at       TIMESTAMPTZ NOT NULL,
       credit_card      VARCHAR(16) NOT NULL,
       currency         VARCHAR(3) NOT NULL,
       email            TEXT NOT NULL,
       is_active        BOOLEAN NOT NULL,
       country          VARCHAR(3) NOT NULL,
       num_logins       INT,
       password_hash    VARCHAR(32),
       username         TEXT NOT NULL
);

CREATE TABLE transactions (
       id               INT PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
       amount           FLOAT NOT NULL,
       currency         VARCHAR(3) NOT NULL,
       description      TEXT,
       timestamp        TIMESTAMPTZ NOT NULL,
       user_id          INT NOT NULL,
       FOREIGN KEY (user_id) REFERENCES users(id)
);