CREATE TABLE logs (
  id SERIAL PRIMARY KEY,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  log_text TEXT
);

CREATE TABLE rules (
  id SERIAL PRIMARY KEY,
  rule_name TEXT,
  rule_description TEXT
);
