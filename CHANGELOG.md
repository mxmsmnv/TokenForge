# Changelog

## [100] - 2026-06-26

- Added `ProcessTokenForge` admin process for token management.
- Added Apple preset loader and Apple Profiles import/export UI.
- Added diagnostics panel with copy + JSON export action.
- Added post-load automatic private key validation for RS256/ES256 presets.
- Added session activity log and admin action rate limiting.
- Hardened admin HTML escaping for profile, form and JWT output.
- Aligned `/site/...` private key path checks with runtime key loading.
- Restricted ES256 signing and validation to EC P-256 keys.
- Fingerprinted cached JWT entries by cache key and token options.
- Added module metadata for PHP requirements and admin process installation.
- Redesigned the admin dashboard in an Ichiban-style layout with provider playbooks for Apple WeatherKit, Android/Firebase, Samsung services and generic APIs.
- Added expanded field notes and descriptions throughout the admin UI.
- Added provider-specific quick presets for Apple WeatherKit, Android/Firebase and Samsung-style service assertions.
- Added clearer cache/key handling guidance in the dashboard and generator UI.
- Expanded Apple preset guidance with Apple service examples and value-source notes while keeping form labels provider-neutral.
- Removed duplicate module status card, filled the healthy dashboard battery state, and added official Apple documentation links.
- Added module settings for admin defaults, reordered Apple setup so technical fields come before examples, and renamed the profile tab to Apple Profiles.
- Made quick presets generate immediately with inline demo signing material, avoiding missing private-key file errors during first-run testing.
- Routed successful Apple preset setup to the generator tab so the prepared JWT fields are immediately visible.
