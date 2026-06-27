# TokenForge

![TokenForge](assets/tokenforge-illustration.png)

TokenForge is a lightweight JWT/signature toolkit for ProcessWire modules and integrations. It creates, signs and caches `HS256`, `RS256` and `ES256` JWTs for external services such as Apple WeatherKit, Android/Firebase-style service accounts, Samsung services and generic bearer-token APIs.

If this project helps your work, consider supporting future development: [GitHub Sponsors](https://github.com/sponsors/mxmsmnv) or [smnv.org/sponsor](https://smnv.org/sponsor/).

## Author

Maxim Semenov  
[smnv.org](https://smnv.org)  
[maxim@smnv.org](mailto:maxim@smnv.org)

## What is TokenForge

TokenForge is a reusable ProcessWire module for modules that need signed tokens when authenticating with external APIs.

- Generates JWT tokens with `HS256`, `RS256` and `ES256`.
- Supports standalone ES256 signing for Apple `.p8` keys.
- Includes admin playbooks and presets for Apple, Android/Firebase, Samsung-style service assertions and generic APIs.
- Quick presets include demo signing material so the generator can be tested immediately.
- Converts OpenSSL DER ECDSA signatures to JOSE `R || S` format.
- Supports cached token creation through ProcessWire cache.
- Provides strict TTL enforcement against expired payloads.
- Loads private keys from files without storing key contents in module settings.
- Provides a superuser-only admin UI for generation, validation, diagnostics, profiles and provider-oriented setup guidance.

## What TokenForge is not

TokenForge is not a REST API authentication module. It is a reusable JWT/signature toolkit for ProcessWire modules that need to authenticate with external services.

It does not:

- expose a REST API;
- manage frontend or backend user login;
- replace AppApi, RestApi or ProcessWire permissions;
- store global service credentials in module settings.

## Installation

Requires PHP 8.1+ and ProcessWire 3+.

1. Copy the `TokenForge` folder into `/site/modules/`.
2. In ProcessWire Admin, refresh module list.
3. Install `TokenForge` (the `ProcessTokenForge` admin process is installed with it).
4. Open `/admin/setup/token-forge/` to use the management UI.

## Module settings

TokenForge settings are intentionally limited to safe admin defaults:

- default cached token TTL shown in generator and presets;
- private key path hint used in placeholders;
- cache key prefix hint used in examples;
- visibility of official documentation links.

Settings do not store private keys, shared secrets or generated JWTs.

## Basic usage

```php
$tokenForge = $modules->get('TokenForge');

$jwt = $tokenForge->createJwt([
    'algorithm' => 'HS256',
    'secret' => 'super-long-secret',
    'payload' => [
        'iss' => 'my-service',
        'iat' => time(),
        'exp' => time() + 3600,
        'aud' => 'api.example.com',
    ],
]);
```

## ES256 usage

ES256 requires an EC P-256 private key. Apple WeatherKit `.p8` keys use this format.

```php
$jwt = $modules->get('TokenForge')->createJwt([
    'algorithm' => 'ES256',
    'key_id' => 'ABC123DEFG',
    'private_key_path' => '/site/assets/private/AuthKey_ABC123DEFG.p8',
    'headers' => [
        'id' => 'TEAMID.org.smnv.weather',
    ],
    'payload' => [
        'iss' => 'TEAMID',
        'iat' => time(),
        'exp' => time() + 3600,
        'sub' => 'org.smnv.weather',
    ],
]);
```

## Apple service tokens

Several Apple APIs use ES256 JWTs signed with an Apple `.p8` private key. TokenForge's Apple preset is a starting point, not a WeatherKit-only form.

Common examples:

- WeatherKit REST API: Team ID, Services ID, Key ID, `.p8`.
- MapKit JS / Apple Maps Server API: Team ID, Maps ID, Key ID, `.p8`.
- APNs provider tokens: Team ID, APNs Key ID, `.p8`.
- App Store Connect / App Store Server APIs: Issuer ID, Key ID, `.p8`.
- MusicKit / DeviceCheck: Team ID, Key ID, `.p8`.

## Apple WeatherKit example

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

$url = 'https://weatherkit.apple.com/api/v1/weather/en_US/40.1013/-75.3836?dataSets=currentWeather,forecastDaily,forecastHourly';

$headers = [
    'Authorization: Bearer ' . $token,
    'Accept: application/json',
];
```

## HS256 example

```php
$jwt = $modules->get('TokenForge')->createJwt([
    'algorithm' => 'HS256',
    'secret' => 'super-long-secret',
    'key_id' => 'shared-secret-key',
    'payload' => [
        'iss' => 'local-service',
        'iat' => time(),
        'exp' => time() + 1800,
    ],
]);
```

## RS256 example

```php
$jwt = $modules->get('TokenForge')->createJwt([
    'algorithm' => 'RS256',
    'key_id' => 'rsa-key-id',
    'private_key_path' => '/site/assets/private/rsa-private-key.pem',
    'payload' => [
        'iss' => 'enterprise-service',
        'iat' => time(),
        'exp' => time() + 3600,
    ],
]);
```

## Caching tokens

Use `createCachedJwt($cacheKey, $options)` for API tokens that can be reused until expiry.

```php
$jwt = $modules->get('TokenForge')->createCachedJwt('meteo_apple_weatherkit', [
    'ttl' => 3300,
    'algorithm' => 'ES256',
    'key_id' => $keyId,
    'private_key_path' => $privateKeyPath,
    'headers' => [
        'id' => $teamId . '.' . $serviceId,
    ],
    'payload' => [
        'iss' => $teamId,
        'iat' => time(),
        'exp' => time() + 3600,
        'sub' => $serviceId,
    ],
]);
```

The public cache key names a logical token. Internally, TokenForge also fingerprints the token options, so changing algorithm, key id, TTL, key material or non-temporal claims creates a fresh cached JWT. Temporal claims (`iat`, `exp`, `nbf`) are excluded from the fingerprint so cache-friendly calls that use `time()` still reuse valid cached tokens until TTL expiry.

If `payload.exp` exists, the ProcessWire cache TTL is capped to `exp - time() - 60`.

## Security notes

- No private keys are stored in ProcessWire module settings.
- Admin profiles store reusable non-secret values per user in the ProcessWire cache path.
- Prefer `private_key_path` over inline `private_key`.
- Use strict filesystem permissions for key files.
- Store keys outside web-served public paths when possible.
- TokenForge does not log private keys, secrets or generated JWT values.
- Error messages do not include private key contents, secrets or full JWTs.

## ProcessWire module integration example

Other modules can depend on TokenForge and call its public API:

```php
$tokenForge = $this->wire('modules')->get('TokenForge');

if (!$tokenForge instanceof TokenForge) {
    throw new WireException('This integration requires TokenForge module.');
}

$jwt = $tokenForge->createCachedJwt('my_provider_token', [
    'ttl' => 3300,
    'algorithm' => 'ES256',
    'key_id' => $options['key_id'],
    'private_key_path' => $options['private_key_path'],
    'headers' => [
        'id' => $options['team_id'] . '.' . $options['service_id'],
    ],
    'payload' => [
        'iss' => $options['team_id'],
        'iat' => time(),
        'exp' => time() + 3600,
        'sub' => $options['service_id'],
    ],
]);
```

## Meteo Apple WeatherKit integration

The intended first consumer is a future `apple` provider in the Meteo module.

Meteo should store these settings:

- `apple_team_id`
- `apple_service_id`
- `apple_key_id`
- `apple_private_key_path`

The provider should request:

- `currentWeather`
- `forecastDaily`
- `forecastHourly`

TokenForge usage inside `MeteoProviderApple`:

```php
$tokenForge = $this->module->wire('modules')->get('TokenForge');

if (!$tokenForge instanceof TokenForge) {
    $this->module->setLastError('Apple WeatherKit requires TokenForge module.');
    return false;
}

$jwt = $tokenForge->createCachedJwt('meteo_apple_weatherkit', [
    'ttl' => 3300,
    'algorithm' => 'ES256',
    'key_id' => $opts['apple_key_id'],
    'private_key_path' => $opts['apple_private_key_path'],
    'headers' => [
        'id' => $opts['apple_team_id'] . '.' . $opts['apple_service_id'],
    ],
    'payload' => [
        'iss' => $opts['apple_team_id'],
        'iat' => time(),
        'exp' => time() + 3600,
        'sub' => $opts['apple_service_id'],
    ],
]);
```

Meteo should normalize Apple WeatherKit data into its existing provider format:

- `location`
- `current`
- `hourly`
- `daily`
- `units`
- `updated_at`
- `provider` (`Apple Weather`)
- `provider_url` (`https://developer.apple.com/weatherkit/`)
- `attribution` (`Weather`)
- optional `raw` debug payload

## Process module (admin UI)

After installation you get an admin page at:

- URL: `/admin/setup/token-forge/`
- Class: `ProcessTokenForge`

You can use it to:

- generate signed JWTs and inspect decoded header/payload/signature parts;
- start from Apple WeatherKit, Android/Firebase, Samsung-style or generic API presets;
- load and export Apple WeatherKit preset values;
- import Apple preset profile JSON from the Apple Profiles tab;
- validate key sources before token generation;
- view diagnostics and download diagnostics JSON;
- clear cached JWT entries by cache key;
- view and clear a session activity log.

## Diagnostics payload format

The admin export `Export diagnostics as file` contains:

- `generated_at` (UTC ISO timestamp)
- `checks` with `label`, `status` (`ok`, `warning`, `error`) and `details`
- `context` with `requested_algorithm` and `private_key_path`

## Troubleshooting notes

- If `OpenSSL extension` check fails, enable OpenSSL for the web PHP process.
- If `Private key path` is not readable, verify file existence and filesystem permissions for the same user that runs PHP.
- `/site/...` private key paths are resolved relative to the ProcessWire root.
- If auto key validation reports an issue, correct the key source and re-run the preset/import flow.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and update notes.

## License

MIT

See [LICENSE](LICENSE) for full terms.
