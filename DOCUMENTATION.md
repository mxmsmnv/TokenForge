# TokenForge Documentation

## Author

Maxim Semenov  
[smnv.org](https://smnv.org)  
[maxim@smnv.org](mailto:maxim@smnv.org)

## Installation

Requires PHP 8.1+.

1. Copy the `TokenForge` folder to `/site/modules/`.
2. In ProcessWire Admin, refresh modules.
3. Install `TokenForge` (the `ProcessTokenForge` admin process is installed with it).
4. Open the admin page: `/admin/setup/token-forge/`.

## Module settings

The module configuration page contains admin defaults only:

- default cached token TTL;
- private key path hint for placeholders;
- cache key prefix hint for examples;
- toggle for official documentation links in helper panels.

Private keys, shared secrets and generated JWTs are not saved in module settings.

## Usage

### Core API

Create signed JWTs with `createJwt($options)`.

```php
$tokenForge = $modules->get('TokenForge');

$jwt = $tokenForge->createJwt([
    'algorithm' => 'HS256',
    'secret' => 'super-long-secret',
    'headers' => ['kid' => 'my-key-id'],
    'payload' => [
        'iss' => 'my-service',
        'iat' => time(),
        'exp' => time() + 3600,
        'aud' => 'api.example.com',
    ],
]);
```

Supported algorithms:

- `HS256` — `secret`
- `RS256` — private key (`private_key` or `private_key_path`)
- `ES256` — EC P-256 private key (`private_key` or `private_key_path`)

### Cached tokens

For cache-friendly integrations use `createCachedJwt($cacheKey, $options)`.

The public cache key names a logical token. Internally, TokenForge also fingerprints
the token options, so changing algorithm, key id, TTL, key material or non-temporal
claims creates a fresh cached JWT instead of returning an older token for the same
public key. Temporal claims (`iat`, `exp`, `nbf`) are excluded from the fingerprint so
cache-friendly calls that use `time()` still reuse valid cached tokens until TTL expiry.

```php
$token = $tokenForge->createCachedJwt('apple_weatherkit', [
    'ttl' => 3300,
    'algorithm' => 'ES256',
    'key_id' => 'APPLE_KEY_ID',
    'private_key_path' => '/site/assets/private/AuthKey_APPLE_KEY_ID.p8',
    'headers' => ['id' => 'TEAMID.com.example.weather'],
    'payload' => [
        'iss' => 'TEAMID',
        'iat' => time(),
        'exp' => time() + 3600,
        'sub' => 'com.example.weather',
    ],
]);
```

## Process module (`ProcessTokenForge`)

Open `/admin/setup/token-forge/` in ProcessWire Admin.

You can:

- generate and inspect JWTs (header, payload, signature);
- start from provider-oriented presets for Apple WeatherKit, Android/Firebase, Samsung-style service assertions and generic APIs;
- test quick presets immediately with demo signing material, then replace identifiers and keys before real provider use;
- load Apple preset values quickly;
- import/export Apple preset profile JSON in the Apple Profiles tab;
- validate private keys;
- view diagnostics and download diagnostics JSON;
- clear cached JWT entries by cache key;
- review and clear activity log.

The dashboard is intentionally organized by integration playbook:

- **Apple services**: ES256, issuer/team ID, service/maps/bundle identifier where required, Key ID and `.p8` private key path.
- **Android/Firebase and Samsung-style APIs**: usually RS256 service assertions or OAuth-style JWT assertions before an access-token exchange.
- **Generic APIs**: HS256, RS256 or ES256 JWT bearer/client assertions where the provider documentation defines the required claims.

## Apple service tokens

TokenForge includes a first-class Apple service preset because several Apple APIs
use ES256 JWTs signed with a downloaded `.p8` private key. The same form can be
adapted to different Apple services by changing `iss`, `sub`, `aud`, `bid` or
other provider-specific claims.

Examples:

- WeatherKit REST API: Team ID, Services ID, Key ID, `.p8`.
- MapKit JS / Apple Maps Server API: Team ID, Maps ID, Key ID, `.p8`.
- APNs provider tokens: Team ID, APNs Key ID, `.p8`.
- App Store Connect / App Store Server APIs: Issuer ID, Key ID, `.p8`.
- MusicKit / DeviceCheck: Team ID, Key ID, `.p8`.

Where to get values:

- Team ID: Apple Developer Account membership.
- Services ID / Maps ID / Bundle ID: Certificates, Identifiers & Profiles → Identifiers.
- Key ID and `.p8`: Certificates, Identifiers & Profiles → Keys.
- Issuer ID: App Store Connect → Users and Access → Integrations / API Keys.

### WeatherKit request

```php
$token = $modules->get('TokenForge')->createCachedJwt('apple_weatherkit', [
    'ttl' => 3300,
    'algorithm' => 'ES256',
    'key_id' => 'APPLE_KEY_ID',
    'private_key_path' => '/site/assets/private/AuthKey_APPLE_KEY_ID.p8',
    'headers' => [
        'id' => 'APPLE_TEAM_ID.com.example.weather',
    ],
    'payload' => [
        'iss' => 'APPLE_TEAM_ID',
        'iat' => time(),
        'exp' => time() + 3600,
        'sub' => 'com.example.weather',
    ],
]);

$headers = [
    'Authorization: Bearer ' . $token,
    'Accept: application/json',
];
```

Initial WeatherKit data sets:

- `currentWeather`
- `forecastDaily`
- `forecastHourly`

## Meteo integration notes

Meteo should add an `apple` provider that depends on TokenForge for the WeatherKit
developer token.

Suggested Meteo settings:

- `apple_team_id`
- `apple_service_id`
- `apple_key_id`
- `apple_private_key_path`

Provider behavior:

- return `false` and set a clear module error if TokenForge is missing;
- use `createCachedJwt('meteo_apple_weatherkit', ...)`;
- send `Authorization: Bearer <JWT>` to WeatherKit;
- normalize Apple data into Meteo's existing `location`, `current`, `hourly`, `daily`, `units`, `updated_at`, `provider`, `provider_url`, `attribution` shape;
- convert metric/SI values to imperial when Meteo is configured for imperial output.

## Apple preset profile format

JSON profile payload contains:

- `schema` (`tokenforge.apple-preset-profile`)
- `version`
- `apple_team_id`
- `apple_service_id`
- `apple_key_id`
- `apple_private_key_path`
- token-related fields (`algorithm`, `key_id`, `cache_key`, `ttl`, `private_key_path`, `headers_json`, `payload_json`)

Profiles are saved per user in the ProcessWire cache path. They intentionally do not
persist inline private keys or HS256 secrets.

## Diagnostics

Use **Export diagnostics as file** in admin.

Payload format:

- `generated_at`
- `checks`: array of `{ label, status, details }`
  - `status` is `ok`, `warning`, or `error`
- `context`: `requested_algorithm`, `private_key_path`

## Troubleshooting

- OpenSSL is unavailable → enable OpenSSL extension in your PHP configuration.
- Private key path is unreadable → verify file path and filesystem permissions; `/site/...` paths are resolved relative to the ProcessWire root.
- Cache target path warnings → verify cache directory write access.
- Auto key validation issues → check PEM format and source (`private_key` vs `private_key_path`).

## Security notes

- Do not store private keys in ProcessWire module settings.
- Admin profiles store reusable non-secret values per user in the ProcessWire cache path.
- Use strict permissions for key files.
- `TokenForge` does not store private keys or generated JWT content in logs.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and update notes.
