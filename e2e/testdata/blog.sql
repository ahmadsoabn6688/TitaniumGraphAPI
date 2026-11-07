-- End-to-end fixture: the demo blog schema from example/seed.sql, loaded into
-- a fresh per-test database created by the e2e harness. It must NOT contain
-- CREATE/DROP/ALTER DATABASE or USE statements (the harness rejects them):
-- every statement runs inside the throwaway gqlgate_e2e_* database.
--
-- Loaded by a naive splitter (same rules as example/seed): `--` comment lines
-- are dropped and statements are split on `;`, so no semicolons inside string
-- literals.

-- users doubles as the identity table for jwt.role_lookup tests.
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

-- Native vector search (VECTOR column + VEC_*_DISTANCE).
CREATE TABLE documents (
    id        BIGINT AUTO_INCREMENT PRIMARY KEY,
    title     VARCHAR(100) NOT NULL,
    embedding VECTOR(3)    NULL
);

-- Target table for after-insert audit hooks.
CREATE TABLE audit_log (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    table_name VARCHAR(64) NOT NULL,
    op         VARCHAR(16) NOT NULL,
    role       VARCHAR(32) NOT NULL,
    row_count  INT         NOT NULL,
    created_at TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Users 1-3 are authors (3 is inactive), 4 is an admin.
INSERT INTO users (id, username, password, role, name, email, is_active, balance, metadata) VALUES
  (1, 'ada',   '$2a$10$devhash.ada',   'author', 'Ada Lovelace',  'ada@example.com',   1, 120.50, '{"tags": ["founder"], "tier": "gold"}'),
  (2, 'grace', '$2a$10$devhash.grace', 'author', 'Grace Hopper',  'grace@example.com', 1,  75.00, '{"tags": ["navy"], "tier": "silver"}'),
  (3, 'alan',  '$2a$10$devhash.alan',  'author', 'Alan Turing',   'alan@example.com',  0,   0.00, NULL),
  (4, 'root',  '$2a$10$devhash.root',  'admin',  'Root Admin',    'root@example.com',  1,   0.00, NULL);

-- Post 2 is the only unpublished one (hidden from anonymous) and has no
-- comments, so a delete attempt on it is never blocked by a foreign key.
INSERT INTO posts (id, author_id, title, body, published, views, rating, published_on) VALUES
  (1, 1, 'Notes on the Analytical Engine', 'First program ever written.',        1, 420, 4.9, '2026-01-15'),
  (2, 1, 'Draft: poetry and math',         'Unpublished musings.',               0,   3, NULL, NULL),
  (3, 2, 'Compilers for humans',           'Why COBOL happened.',                1, 250, 4.5, '2026-03-02'),
  (4, 3, 'On computable numbers',          'With an application to the Entscheidungsproblem.', 1, 999, 5.0, '2026-02-20');

INSERT INTO comments (id, post_id, user_id, body) VALUES
  (1, 1, 2, 'Brilliant work!'),
  (2, 1, 3, 'This inspired my paper.'),
  (3, 3, 1, 'COBOL is still everywhere.'),
  (4, 4, 1, 'Foundational.'),
  (5, 4, 2, 'Agreed, a classic.');

INSERT INTO documents (id, title, embedding) VALUES
  (1, 'alpha', '[1,2,3]'),
  (2, 'beta',  '[9,9,9]'),
  (3, 'gamma', '[1,2,4]'),
  (4, 'delta', NULL);
