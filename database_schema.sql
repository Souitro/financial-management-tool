-- ============================================================
-- SOUITRO INNOVATIVE TECH SOLUTIONS
-- Database Schema v1.0
-- Engine: InnoDB | Charset: utf8mb4
-- ============================================================

CREATE DATABASE IF NOT EXISTS souitro_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE souitro_db;

-- ────────────────────────────────────────────────────────────
-- TABLE: companies
-- Supports white-labelling / rebranding per organisation.
-- ────────────────────────────────────────────────────────────
CREATE TABLE companies (
    id               INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    company_name     VARCHAR(120)     NOT NULL,
    logo_url         VARCHAR(500)     DEFAULT NULL,
    primary_color    VARCHAR(7)       NOT NULL DEFAULT '#0e6fcb',   -- hex
    secondary_color  VARCHAR(7)       NOT NULL DEFAULT '#00c8c8',
    accent_color     VARCHAR(7)       NOT NULL DEFAULT '#ff5e3a',
    domain           VARCHAR(120)     DEFAULT NULL,  -- optional vanity domain
    is_active        TINYINT(1)       NOT NULL DEFAULT 1,
    created_at       TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP
                                      ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_company_name (company_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- TABLE: users
-- Roles: 'CEO' = power admin, 'Manager', 'Employee'
-- ────────────────────────────────────────────────────────────
CREATE TABLE users (
    id               INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    company_id       INT UNSIGNED     NOT NULL,
    name             VARCHAR(120)     NOT NULL,
    email            VARCHAR(180)     NOT NULL,
    password_hash    VARCHAR(255)     NOT NULL,    -- bcrypt / Argon2id
    role             ENUM('CEO','Manager','Employee') NOT NULL DEFAULT 'Employee',
    avatar_url       VARCHAR(500)     DEFAULT NULL,
    is_active        TINYINT(1)       NOT NULL DEFAULT 1,
    last_login       TIMESTAMP        DEFAULT NULL,
    created_at       TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP
                                      ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_email_company (email, company_id),
    KEY fk_users_company (company_id),
    CONSTRAINT fk_users_company
        FOREIGN KEY (company_id) REFERENCES companies (id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- TABLE: clients
-- Customers/clients that belong to a company.
-- ────────────────────────────────────────────────────────────
CREATE TABLE clients (
    id               INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    company_id       INT UNSIGNED     NOT NULL,
    name             VARCHAR(120)     NOT NULL,
    email            VARCHAR(180)     DEFAULT NULL,
    phone            VARCHAR(30)      DEFAULT NULL,
    address          TEXT             DEFAULT NULL,
    vat_number       VARCHAR(40)      DEFAULT NULL,
    is_active        TINYINT(1)       NOT NULL DEFAULT 1,
    created_at       TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY fk_clients_company (company_id),
    CONSTRAINT fk_clients_company
        FOREIGN KEY (company_id) REFERENCES companies (id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- TABLE: inventory
-- Stock items belonging to a company.
-- ────────────────────────────────────────────────────────────
CREATE TABLE inventory (
    id               INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    company_id       INT UNSIGNED     NOT NULL,
    created_by       INT UNSIGNED     NOT NULL,  -- user_id
    sku              VARCHAR(80)      NOT NULL,
    name             VARCHAR(200)     NOT NULL,
    description      TEXT             DEFAULT NULL,
    category         VARCHAR(80)      DEFAULT NULL,
    unit_price       DECIMAL(12,2)    NOT NULL DEFAULT 0.00,
    cost_price       DECIMAL(12,2)    NOT NULL DEFAULT 0.00,
    quantity_on_hand INT              NOT NULL DEFAULT 0,
    reorder_level    INT              NOT NULL DEFAULT 10,
    is_active        TINYINT(1)       NOT NULL DEFAULT 1,
    created_at       TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP
                                      ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_sku_company (sku, company_id),
    KEY fk_inventory_company (company_id),
    KEY fk_inventory_user   (created_by),
    CONSTRAINT fk_inventory_company
        FOREIGN KEY (company_id) REFERENCES companies (id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_inventory_user
        FOREIGN KEY (created_by) REFERENCES users (id)
        ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- TABLE: invoices
-- ────────────────────────────────────────────────────────────
CREATE TABLE invoices (
    id               INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    company_id       INT UNSIGNED     NOT NULL,
    client_id        INT UNSIGNED     NOT NULL,
    created_by       INT UNSIGNED     NOT NULL,  -- user_id
    invoice_number   VARCHAR(40)      NOT NULL,
    issue_date       DATE             NOT NULL,
    due_date         DATE             NOT NULL,
    subtotal         DECIMAL(12,2)    NOT NULL DEFAULT 0.00,
    tax_rate         DECIMAL(5,2)     NOT NULL DEFAULT 15.00,  -- VAT %
    tax_amount       DECIMAL(12,2)    NOT NULL DEFAULT 0.00,
    total_amount     DECIMAL(12,2)    NOT NULL DEFAULT 0.00,
    status           ENUM('draft','sent','paid','overdue','cancelled')
                                      NOT NULL DEFAULT 'draft',
    notes            TEXT             DEFAULT NULL,
    created_at       TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP
                                      ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_invoice_no_company (invoice_number, company_id),
    KEY fk_invoices_company  (company_id),
    KEY fk_invoices_client   (client_id),
    KEY fk_invoices_creator  (created_by),
    CONSTRAINT fk_invoices_company
        FOREIGN KEY (company_id)  REFERENCES companies (id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_invoices_client
        FOREIGN KEY (client_id)   REFERENCES clients (id)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT fk_invoices_creator
        FOREIGN KEY (created_by)  REFERENCES users (id)
        ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- TABLE: invoice_items
-- Line items for each invoice.
-- ────────────────────────────────────────────────────────────
CREATE TABLE invoice_items (
    id               INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    invoice_id       INT UNSIGNED     NOT NULL,
    inventory_id     INT UNSIGNED     DEFAULT NULL,  -- nullable (custom lines)
    description      VARCHAR(300)     NOT NULL,
    quantity         DECIMAL(10,2)    NOT NULL DEFAULT 1,
    unit_price       DECIMAL(12,2)    NOT NULL DEFAULT 0.00,
    line_total       DECIMAL(12,2)    NOT NULL DEFAULT 0.00,
    PRIMARY KEY (id),
    KEY fk_ii_invoice   (invoice_id),
    KEY fk_ii_inventory (inventory_id),
    CONSTRAINT fk_ii_invoice
        FOREIGN KEY (invoice_id)    REFERENCES invoices (id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_ii_inventory
        FOREIGN KEY (inventory_id)  REFERENCES inventory (id)
        ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- TABLE: payments
-- Records payments received against invoices.
-- ────────────────────────────────────────────────────────────
CREATE TABLE payments (
    id               INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    company_id       INT UNSIGNED     NOT NULL,
    invoice_id       INT UNSIGNED     NOT NULL,
    recorded_by      INT UNSIGNED     NOT NULL,   -- user_id
    amount           DECIMAL(12,2)    NOT NULL,
    payment_date     DATE             NOT NULL,
    method           ENUM('EFT','cash','card','other') NOT NULL DEFAULT 'EFT',
    reference        VARCHAR(100)     DEFAULT NULL,
    notes            TEXT             DEFAULT NULL,
    created_at       TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY fk_pay_company  (company_id),
    KEY fk_pay_invoice  (invoice_id),
    KEY fk_pay_user     (recorded_by),
    CONSTRAINT fk_pay_company
        FOREIGN KEY (company_id)  REFERENCES companies (id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_pay_invoice
        FOREIGN KEY (invoice_id)  REFERENCES invoices (id)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT fk_pay_user
        FOREIGN KEY (recorded_by) REFERENCES users (id)
        ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- TABLE: personal_finance
-- STRICTLY CONFIDENTIAL.
-- Readable ONLY by the owning user_id (enforced at app layer).
-- CEOs can view aggregate totals but never individual rows.
-- ────────────────────────────────────────────────────────────
CREATE TABLE personal_finance (
    id                  INT UNSIGNED   NOT NULL AUTO_INCREMENT,
    user_id             INT UNSIGNED   NOT NULL,  -- owner — strictly private
    month_year          CHAR(7)        NOT NULL,  -- format: YYYY-MM
    gross_salary        DECIMAL(12,2)  NOT NULL DEFAULT 0.00,
    tax_amount          DECIMAL(12,2)  NOT NULL DEFAULT 0.00,
    other_deductions    DECIMAL(12,2)  NOT NULL DEFAULT 0.00,
    net_salary          DECIMAL(12,2)  NOT NULL DEFAULT 0.00,
    total_expenses      DECIMAL(12,2)  NOT NULL DEFAULT 0.00,
    total_savings       DECIMAL(12,2)  NOT NULL DEFAULT 0.00,
    -- JSON blob storing expense line items: [{name, amount, category}]
    expense_breakdown   JSON           DEFAULT NULL,
    -- AI / rule-based recommendations stored as text after calculation
    recommendations     TEXT           DEFAULT NULL,
    -- health score 0-100
    financial_health_score TINYINT UNSIGNED DEFAULT 0,
    created_at          TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP
                                       ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_month (user_id, month_year),
    KEY fk_pf_user (user_id),
    CONSTRAINT fk_pf_user
        FOREIGN KEY (user_id) REFERENCES users (id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='STRICTLY CONFIDENTIAL — access restricted to owning user only';

-- ────────────────────────────────────────────────────────────
-- TABLE: audit_log
-- Immutable record of sensitive actions for compliance.
-- ────────────────────────────────────────────────────────────
CREATE TABLE audit_log (
    id          BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
    user_id     INT UNSIGNED     DEFAULT NULL,
    company_id  INT UNSIGNED     DEFAULT NULL,
    action      VARCHAR(120)     NOT NULL,
    target      VARCHAR(120)     DEFAULT NULL,  -- e.g. 'personal_finance:42'
    ip_address  VARCHAR(45)      DEFAULT NULL,
    user_agent  VARCHAR(300)     DEFAULT NULL,
    created_at  TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_al_user    (user_id),
    KEY idx_al_company (company_id),
    KEY idx_al_action  (action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- SEED: Default company + CEO account
-- Password: Admin@Souitro1  (change immediately in production)
-- Hash generated with: password_hash('Admin@Souitro1', PASSWORD_ARGON2ID)
-- ────────────────────────────────────────────────────────────
INSERT INTO companies (company_name, primary_color, secondary_color, accent_color)
VALUES ('Souitro Innovative Tech Solutions', '#0e6fcb', '#00c8c8', '#ff5e3a');

INSERT INTO users (company_id, name, email, password_hash, role)
VALUES (
    1,
    'System Administrator',
    'admin@souitro.co.za',
    '$argon2id$v=19$m=65536,t=4,p=1$seed_hash_replace_in_production',
    'CEO'
);


-- ============================================================
-- SOUITRO — OTP & Session Management Schema
-- Run this AFTER the main schema from Block 1 previously
-- ============================================================

USE souitro_db;

-- ────────────────────────────────────────────────────────────
-- TABLE: user_otp
-- Stores one-time passwords generated by admin for new users.
-- OTP is single-use and expires after 24 hours.
-- ────────────────────────────────────────────────────────────
CREATE TABLE user_otp (
    id           INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    user_id      INT UNSIGNED  NOT NULL,
    otp_hash     VARCHAR(255)  NOT NULL,   -- bcrypt hash of the OTP code
    otp_type     ENUM('first_login','password_reset') NOT NULL DEFAULT 'first_login',
    is_used      TINYINT(1)    NOT NULL DEFAULT 0,
    expires_at   DATETIME      NOT NULL,
    created_by   INT UNSIGNED  NOT NULL,   -- admin user_id who generated it
    used_at      DATETIME      DEFAULT NULL,
    created_at   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY fk_otp_user    (user_id),
    KEY fk_otp_creator (created_by),
    CONSTRAINT fk_otp_user
        FOREIGN KEY (user_id)    REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_otp_creator
        FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- TABLE: user_sessions
-- Tracks active sessions for audit + forced logout capability.
-- ────────────────────────────────────────────────────────────
CREATE TABLE user_sessions (
    id           VARCHAR(128)  NOT NULL,   -- PHP session ID
    user_id      INT UNSIGNED  NOT NULL,
    ip_address   VARCHAR(45)   NOT NULL,
    user_agent   VARCHAR(300)  DEFAULT NULL,
    last_active  DATETIME      NOT NULL,
    created_at   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY fk_sess_user (user_id),
    CONSTRAINT fk_sess_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- ALTER users: add password_set flag so we know if user has
-- set their own password (vs still using OTP flow).
-- Also add failed_attempts + locked_until for brute-force protection.
-- ────────────────────────────────────────────────────────────
ALTER TABLE users
    ADD COLUMN password_is_set   TINYINT(1)  NOT NULL DEFAULT 0
        COMMENT '0 = must set password via OTP flow, 1 = user has set their own password'
        AFTER password_hash,
    ADD COLUMN failed_attempts   TINYINT     NOT NULL DEFAULT 0
        AFTER password_is_set,
    ADD COLUMN locked_until      DATETIME    DEFAULT NULL
        AFTER failed_attempts;

-- ────────────────────────────────────────────────────────────
-- Update seed CEO to have password set (so they can log in normally).
-- In production: run the PHP script to hash and insert properly.
-- ────────────────────────────────────────────────────────────
UPDATE users
SET    password_is_set = 1
WHERE  id = 1;