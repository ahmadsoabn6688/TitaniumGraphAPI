-- Dev schema for the gqlgate example config. Idempotent: drops and recreates.
DROP DATABASE IF EXISTS appdb;
CREATE DATABASE appdb CHARACTER SET utf8mb4;
USE appdb;

-- users doubles as the identity table for jwt.role_lookup: your signup
-- service writes username/password(hash)/role, and gqlgate only reads role.
CREATE TABLE users (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    username   VARCHAR(50)   NOT NULL UNIQUE,
    password   VARCHAR(255)  NOT NULL,
    role       VARCHAR(32)   NOT NULL DEFAULT 'author',
    name       VARCHAR(100)  NOT NULL,
    email      VARCHAR(255)  NOT NULL UNIQUE,
    is_active  TINYINT(1)    NOT NULL DEFAULT 1,
    balance    DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    metadata   JSON          NULL,
    created_at TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE posts (
    id           BIGINT AUTO_INCREMENT PRIMARY KEY,
    author_id    BIGINT       NOT NULL,
    title        VARCHAR(200) NOT NULL,
    body         TEXT         NULL,
    published    TINYINT(1)   NOT NULL DEFAULT 0,
    views        INT          NOT NULL DEFAULT 0,
    rating       DOUBLE       NULL,
    published_on DATE         NULL,
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_posts_author FOREIGN KEY (author_id) REFERENCES users (id)
);

CREATE TABLE comments (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    post_id    BIGINT    NOT NULL,
    user_id    BIGINT    NOT NULL,
    body       TEXT      NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_comments_post FOREIGN KEY (post_id) REFERENCES posts (id),
    CONSTRAINT fk_comments_user FOREIGN KEY (user_id) REFERENCES users (id)
);

-- password values are bcrypt-hash placeholders; your signup service owns them.
INSERT INTO users (id, username, password, role, name, email, is_active, balance, metadata) VALUES
  (1, 'ada',   '$2a$10$devhash.ada',   'author', 'Ada Lovelace',  'ada@example.com',   1, 120.50, '{"tags": ["founder"], "tier": "gold"}'),
  (2, 'grace', '$2a$10$devhash.grace', 'author', 'Grace Hopper',  'grace@example.com', 1,  75.00, '{"tags": ["navy"], "tier": "silver"}'),
  (3, 'alan',  '$2a$10$devhash.alan',  'author', 'Alan Turing',   'alan@example.com',  0,   0.00, NULL),
  (4, 'root',  '$2a$10$devhash.root',  'admin',  'Root Admin',    'root@example.com',  1,   0.00, NULL);

INSERT INTO posts (id, author_id, title, body, published, views, rating, published_on) VALUES
  (1, 1, 'Notes on the Analytical Engine', 'First program ever written.',        1, 420, 4.9, '2026-01-15'),
  (2, 1, 'Draft: poetry and math',         'Unpublished musings.',               0,   3, NULL, NULL),
  (3, 2, 'Compilers for humans',           'Why COBOL happened.',                1, 250, 4.5, '2026-03-02'),
  (4, 3, 'On computable numbers',          'With an application to the Entscheidungsproblem.', 1, 999, 5.0, '2026-02-20');

INSERT INTO comments (post_id, user_id, body) VALUES
  (1, 2, 'Brilliant work!'),
  (1, 3, 'This inspired my paper.'),
  (3, 1, 'COBOL is still everywhere.'),
  (4, 1, 'Foundational.'),
  (4, 2, 'Agreed, a classic.');

-- Demonstrates TiDB native vector search (VECTOR column + VEC_*_DISTANCE).
CREATE TABLE documents (
    id        BIGINT AUTO_INCREMENT PRIMARY KEY,
    title     VARCHAR(100) NOT NULL,
    embedding VECTOR(3)    NULL          -- nullable: rows without an embedding are skipped by vector search
);
INSERT INTO documents (title, embedding) VALUES
    ('alpha', '[1,2,3]'),
    ('beta',  '[9,9,9]'),
    ('gamma', '[1,2,4]'),
    ('delta', NULL);

-- Written by the example "audit" after-insert hook (see example/hooks).
CREATE TABLE audit_log (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    table_name VARCHAR(64) NOT NULL,
    op         VARCHAR(16) NOT NULL,
    role       VARCHAR(32) NOT NULL,
    row_count  INT         NOT NULL,
    created_at TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);
