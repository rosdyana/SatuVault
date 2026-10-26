-- The app account gets its least-privilege grants from `SatuVault migrate --app-user`.
CREATE USER IF NOT EXISTS 'satuvault_app'@'%' IDENTIFIED BY 'demo-app-pass';
