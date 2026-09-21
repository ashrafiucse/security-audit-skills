# Fixture: SSL enforcement off.
Rails.application.configure do
  config.force_ssl = false   # SEC-08
  config.session_store :cookie_store, key: '_vuln_session'
end
