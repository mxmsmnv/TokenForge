<?php namespace ProcessWire;

require_once __DIR__ . '/src/KeyLoader.php';

/**
 * ProcessTokenForge
 *
 * Admin process for TokenForge management:
 * - quick JWT generation (HS256/RS256/ES256)
 * - cached JWT generation
 * - cache key cleanup
 *
 * @author  Maxim Semenov (smnv.org)
 * @version 100
 * @license MIT
 */
class ProcessTokenForge extends Process {
    protected const AUDIT_LIMIT = 12;
    protected const APPLE_PRESET_SESSION_KEY = 'tokenforge_apple_preset';
    protected const APPLE_PRESET_PROFILE_FILE = 'tokenforge-apple-preset-profile.json';
    protected const ACTION_RATE_LIMIT_WINDOW = 60;
    protected const ACTION_RATE_LIMIT_MAX = 20;
    protected const RATE_LIMIT_SESSION_KEY = 'tokenforge_admin_action_rate';

    public static function getModuleInfo(): array {
        return [
            'title'   => 'TokenForge',
            'version' => 100,
            'summary' => 'Admin management UI for TokenForge JWT tooling.',
            'author'  => 'Maxim Semenov',
            'href'    => 'https://smnv.org',
            'page'    => [
                'name'   => 'token-forge',
                'parent' => 'setup',
                'title'  => 'TokenForge',
            ],
            'icon'    => 'key',
            'autoload' => false,
            'singular' => true,
            'requires' => ['TokenForge', 'PHP>=8.1.0'],
        ];
    }

    public function ___execute() {
        if (!$this->user->isSuperuser()) {
            throw new WirePermissionException($this->_('Insufficient permission to access TokenForge admin.'));
        }

        $input = $this->wire('input');
        $modules = $this->wire('modules');
        $cache = $this->wire('cache');
        $tokenForge = $modules->get('TokenForge');
        $adminDefaults = is_object($tokenForge) && method_exists($tokenForge, 'adminDefaults')
            ? $tokenForge->adminDefaults()
            : [
                'default_ttl' => 3300,
                'private_key_base_path' => '/site/assets/private/',
                'cache_key_prefix' => 'provider_',
                'show_official_docs' => 1,
            ];
        $applePreset = $this->session->get(self::APPLE_PRESET_SESSION_KEY);
        $applePreset = is_array($applePreset) ? $applePreset : [];
        $storedProfile = $this->getStoredProfile();
        foreach (['apple_team_id', 'apple_service_id', 'apple_key_id', 'apple_private_key_path'] as $k) {
            if (!isset($applePreset[$k]) || (string)$applePreset[$k] === '') {
                $applePreset[$k] = (string)($storedProfile[$k] ?? '');
            }
        }

        $csrf = $this->session->CSRF;
        $action = (string)$input->post('action', 'string');
        $notice = '';
        $error = '';
        $resultJwt = '';
        $parsedJwt = null;
        $now = time();
        $activeTab = $this->resolveAdminTab((string)$input->get('tab', 'string'));
        $activeTabUrl = $this->adminTabUrl($activeTab);

        if ($action !== '') {
            if (!$this->checkRateLimit($action)) {
                $error = $this->_('Too many requests. Please wait a moment and try again.');
                $this->addLog('admin.ratelimit', 'error', [
                    'action' => $action,
                ]);
                $action = '';
            }
        }

        $form = [
            'algorithm' => (string)$input->post('algorithm', 'string') ?: (string)($storedProfile['algorithm'] ?? 'HS256'),
            'key_id' => (string)$input->post('key_id', 'string') ?: (string)($storedProfile['key_id'] ?? ''),
            'cache_key' => (string)$input->post('cache_key', 'string') ?: (string)($storedProfile['cache_key'] ?? ''),
            'ttl' => (string)$input->post('ttl', 'string') ?: (string)($storedProfile['ttl'] ?? (string)$adminDefaults['default_ttl']),
            'private_key_path' => (string)$input->post('private_key_path', 'string') ?: (string)($storedProfile['private_key_path'] ?? ''),
            'private_key' => (string)$input->post('private_key', 'string'),
            'secret' => (string)$input->post('secret', 'string'),
            'headers_json' => (string)$input->post('headers_json', 'string') ?: (string)($storedProfile['headers_json'] ?? '{ "id": "TEAMID.com.example.weather" }'),
            'payload_json' => (string)$input->post('payload_json', 'string') ?: (string)($storedProfile['payload_json'] ?? '{"iss":"TEAMID","iat":' . $now . ',"exp":' . ($now + 3600) . ',"sub":"com.example.weather"}'),
        ];

        if ($action === 'preset_apple') {
            if (!$csrf->validate()) {
                $this->error($this->_('Invalid request token.'));
                $this->wire('session')->redirect($activeTabUrl);
                return '';
            }

            $teamId = trim((string)$input->post('apple_team_id', 'string'));
            $serviceId = trim((string)$input->post('apple_service_id', 'string'));
            $keyId = trim((string)$input->post('apple_key_id', 'string'));
            $privateKeyPath = trim((string)$input->post('apple_private_key_path', 'string'));

            if ($teamId === '' || $serviceId === '' || $keyId === '') {
                $error = $this->_('Apple service preset requires issuer/team ID, service identifier and key ID.');
            } else {
                $this->session->set(self::APPLE_PRESET_SESSION_KEY, [
                    'apple_team_id' => $teamId,
                    'apple_service_id' => $serviceId,
                    'apple_key_id' => $keyId,
                    'apple_private_key_path' => $privateKeyPath,
                ]);
                $form['algorithm'] = 'ES256';
                $form['key_id'] = $keyId;
                if ($privateKeyPath !== '') {
                    $form['private_key_path'] = $privateKeyPath;
                }
                $form['cache_key'] = 'apple_weatherkit_' . sha1($teamId . '|' . $serviceId . '|' . $keyId);
                $form['ttl'] = (string)$adminDefaults['default_ttl'];
                $form['headers_json'] = json_encode(['id' => $teamId . '.' . $serviceId], JSON_UNESCAPED_SLASHES);
                $form['payload_json'] = json_encode([
                    'iss' => $teamId,
                    'iat' => $now,
                    'exp' => $now + 3600,
                    'sub' => $serviceId,
                ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                $notice = $this->_('Apple service ES256 preset loaded.');
                $this->session->set(self::APPLE_PRESET_SESSION_KEY, [
                    'apple_team_id' => $teamId,
                    'apple_service_id' => $serviceId,
                    'apple_key_id' => $keyId,
                    'apple_private_key_path' => $privateKeyPath,
                ]);
                $this->saveUserProfile($this->session->get(self::APPLE_PRESET_SESSION_KEY), $form);
                $this->autoValidateProfilePrivateKey($form['algorithm'], $form['private_key'], $form['private_key_path'], $notice);
                $this->addLog('preset.apple_loaded', 'ok', [
                    'team_id' => $teamId,
                    'service_id' => $serviceId,
                    'key_id' => $keyId,
                    'private_key_path_hash' => sha1($privateKeyPath),
                ]);
                $activeTab = 'generate-jwt';
                $activeTabUrl = $this->adminTabUrl($activeTab);
            }
        }

        if ($action === 'import_preset_profile') {
            if (!$csrf->validate()) {
                $this->error($this->_('Invalid request token.'));
                $this->wire('session')->redirect($activeTabUrl);
                return '';
            }

            $profileRaw = trim((string)$input->post('preset_profile_json', 'string'));
            if ($profileRaw === '' && isset($_FILES['preset_profile_file']['tmp_name']) && is_uploaded_file($_FILES['preset_profile_file']['tmp_name'])) {
                $tmpName = $_FILES['preset_profile_file']['tmp_name'];
                $maxSize = 131072;
                if (is_file($tmpName) && filesize($tmpName) > $maxSize) {
                    $error = $this->_('Profile file is too large.');
                } else {
                    $uploaded = file_get_contents($tmpName);
                    $profileRaw = $uploaded === false ? '' : trim((string)$uploaded);
                }
            }

            if (!$error) {
                if ($profileRaw === '') {
                    $error = $this->_('Preset profile is empty.');
                } else {
                    $profile = json_decode($profileRaw, true);
                    if (!is_array($profile)) {
                        $error = $this->_('Preset profile JSON is invalid.');
                    } else {
                        $applePreset = [
                            'apple_team_id' => trim((string)($profile['apple_team_id'] ?? '')),
                            'apple_service_id' => trim((string)($profile['apple_service_id'] ?? '')),
                            'apple_key_id' => trim((string)($profile['apple_key_id'] ?? '')),
                            'apple_private_key_path' => trim((string)($profile['apple_private_key_path'] ?? '')),
                        ];
                        $this->session->set(self::APPLE_PRESET_SESSION_KEY, $applePreset);

                        if (trim((string)($profile['algorithm'] ?? '')) !== '') {
                            $form['algorithm'] = trim((string)$profile['algorithm']);
                        }
                        if (trim((string)($profile['cache_key'] ?? '')) !== '') {
                            $form['cache_key'] = trim((string)$profile['cache_key']);
                        }
                        if (trim((string)($profile['ttl'] ?? '')) !== '') {
                            $form['ttl'] = trim((string)$profile['ttl']);
                        }
                        if (trim((string)($profile['key_id'] ?? '')) !== '') {
                            $form['key_id'] = trim((string)$profile['key_id']);
                        }
                        if (trim((string)($profile['private_key_path'] ?? '')) !== '') {
                            $form['private_key_path'] = trim((string)$profile['private_key_path']);
                        }
                        if (trim((string)($profile['private_key'] ?? '')) !== '') {
                            $form['private_key'] = trim((string)$profile['private_key']);
                        }
                        if (trim((string)($profile['headers_json'] ?? '')) !== '') {
                            $form['headers_json'] = (string)$profile['headers_json'];
                        }
                        if (trim((string)($profile['payload_json'] ?? '')) !== '') {
                            $form['payload_json'] = (string)$profile['payload_json'];
                        }

                        $notice = $this->_('Preset profile imported successfully.');
                        $this->saveUserProfile($applePreset, $form);
                        $this->autoValidateProfilePrivateKey($form['algorithm'], $form['private_key'], $form['private_key_path'], $notice);
                        $this->addLog('preset.profile_import', 'ok', [
                            'team_id' => $applePreset['apple_team_id'] ?? '',
                            'service_id' => $applePreset['apple_service_id'] ?? '',
                        ]);
                    }
                }
            }
        }

        if ($action === 'validate_private_key') {
            if (!$csrf->validate()) {
                $this->error($this->_('Invalid request token.'));
                $this->wire('session')->redirect($activeTabUrl);
                return '';
            }

            $algorithm = strtoupper(trim((string)$input->post('algorithm', 'string')));
            $privateKeyPath = trim((string)$input->post('private_key_path', 'string'));
            $privateKey = trim((string)$input->post('private_key', 'string'));
            $validation = $this->validatePrivateKey($algorithm, $privateKey, $privateKeyPath);
            if ($validation['status'] === 'ok') {
                $notice = (string)$validation['message'];
            $this->addLog('jwt.private_key_valid', 'ok', [
                'algorithm' => $algorithm,
                'type' => $validation['type'] ?? '',
                'source' => $validation['source'] ?? '',
            ]);
        } else {
                $error = (string)$validation['message'];
                $this->addLog('jwt.private_key_invalid', 'error', [
                    'algorithm' => $algorithm,
                    'error' => $this->shortenMessage($error),
                ]);
            }
        }

        if ($action === 'export_preset_profile_file') {
            if (!$csrf->validate()) {
                $this->error($this->_('Invalid request token.'));
                $this->wire('session')->redirect($activeTabUrl);
                return '';
            }

            $profilePayload = [
                'schema' => 'tokenforge.apple-preset-profile',
                'version' => 1,
                'generated_at' => gmdate('c'),
                'apple_team_id' => $applePreset['apple_team_id'] ?? '',
                'apple_service_id' => $applePreset['apple_service_id'] ?? '',
                'apple_key_id' => $applePreset['apple_key_id'] ?? '',
                'apple_private_key_path' => $applePreset['apple_private_key_path'] ?? '',
                'algorithm' => $form['algorithm'],
                'key_id' => $form['key_id'],
                'cache_key' => $form['cache_key'],
                'ttl' => $form['ttl'],
                'private_key_path' => $form['private_key_path'],
                'headers_json' => $form['headers_json'],
                'payload_json' => $form['payload_json'],
            ];

            header('Content-Type: application/json; charset=utf-8');
            header('Content-Disposition: attachment; filename="tokenforge-apple-preset-profile.json"');
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            echo json_encode($profilePayload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            $this->addLog('preset.export_profile', 'ok', []);
            exit;
        }

        if ($action === 'export_diagnostics_file') {
            if (!$csrf->validate()) {
                $this->error($this->_('Invalid request token.'));
                $this->wire('session')->redirect($activeTabUrl);
                return '';
            }

            $diagnostics = $this->buildDiagnosticsPayload($form, $tokenForge);
            header('Content-Type: application/json; charset=utf-8');
            header('Content-Disposition: attachment; filename="tokenforge-diagnostics.json"');
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            echo json_encode($diagnostics, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            $this->addLog('diagnostics.export', 'ok', [
                'cache_backend' => is_object($cache) ? get_class($cache) : 'n/a',
            ]);
            exit;
        }

        if ($action === 'clear') {
            if (!$csrf->validate()) {
                $this->error($this->_('Invalid request token.'));
                $this->wire('session')->redirect($activeTabUrl);
                return '';
            }

            $cacheKey = trim((string)$input->post('cache_key'));
            if ($cacheKey === '') {
                $error = $this->_('Cache key is required.');
            } else if (!$tokenForge instanceof TokenForge) {
                $error = $this->_('TokenForge module is not available.');
            } else {
                $tokenForge->clearCachedJwt($cacheKey);
                $notice = sprintf($this->_('Cache key `%s` was cleared.'), $cacheKey);
                $this->addLog('cache.clear', 'ok', [
                    'cache_key_hash' => sha1($cacheKey),
                ]);
            }
        }

        if ($action === 'clear_log') {
            if (!$csrf->validate()) {
                $this->error($this->_('Invalid request token.'));
                $this->wire('session')->redirect($activeTabUrl);
                return '';
            }

            $this->session->set('tokenforge_admin_activity_log', []);
            $this->message($this->_('Activity log cleared.'));
            $this->wire('session')->redirect($activeTabUrl);
            return '';
        }

        if ($action === 'generate') {
            if (!$csrf->validate()) {
                $this->error($this->_('Invalid request token.'));
                $this->wire('session')->redirect($activeTabUrl);
                return '';
            }

            if (!$tokenForge instanceof TokenForge) {
                $error = $this->_('TokenForge module is not available.');
            } else {
                $algorithm = strtoupper(trim((string)$input->post('algorithm', 'string')));
                $keyId = trim((string)$input->post('key_id', 'string'));
                $cacheKey = trim((string)$input->post('cache_key', 'string'));
                $ttl = (string)$input->post('ttl', 'string');
                $privateKeyPath = trim((string)$input->post('private_key_path', 'string'));
                $privateKey = (string)$input->post('private_key', 'string');
                $secret = (string)$input->post('secret', 'string');
                $headersRaw = trim((string)$input->post('headers_json', 'string'));
                $payloadRaw = trim((string)$input->post('payload_json', 'string'));

                $headers = [];
                if ($headersRaw !== '') {
                    $headersDecoded = json_decode($headersRaw, true);
                    if (!is_array($headersDecoded)) {
                        $error = $this->_('Headers must be valid JSON object.');
                    } else {
                        $headers = $headersDecoded;
                    }
                }

                $payloadDecoded = json_decode($payloadRaw, true);
                if (!$error && !is_array($payloadDecoded)) {
                    $error = $this->_('Payload must be valid JSON object.');
                }

                if (!$error && $algorithm === '') {
                    $error = $this->_('Algorithm is required.');
                }

                if (!$error) {
                    $options = [
                        'algorithm' => $algorithm,
                        'payload' => $payloadDecoded,
                    ];

                    if (!empty($keyId)) {
                        $options['key_id'] = $keyId;
                    }
                    if ($headers !== []) {
                        $options['headers'] = $headers;
                    }
                    if ($privateKey !== '') {
                        $options['private_key'] = $privateKey;
                    }
                    if ($privateKeyPath !== '') {
                        $options['private_key_path'] = $privateKeyPath;
                    }
                    if ($secret !== '') {
                        $options['secret'] = $secret;
                    }

                    try {
                        if ($cacheKey !== '') {
                            $options['ttl'] = $ttl === '' ? (int)$adminDefaults['default_ttl'] : (int)$ttl;
                            $resultJwt = $tokenForge->createCachedJwt($cacheKey, $options);
                            $notice = $this->_('Cached token generated successfully.');
                            $this->addLog('jwt.create_cached', 'ok', [
                                'algorithm' => $algorithm,
                                'cache_key_hash' => sha1($cacheKey),
                                'ttl' => (int)$options['ttl'],
                            ]);
                        } else {
                            $resultJwt = $tokenForge->createJwt($options);
                            $notice = $this->_('JWT generated successfully.');
                            $this->addLog('jwt.create', 'ok', [
                                'algorithm' => $algorithm,
                            ]);
                        }
                        $this->saveUserProfile($applePreset, $form);
                        $parsedJwt = $this->parseJwt($resultJwt);
                    } catch (\Throwable $e) {
                        $error = $this->_('Unable to generate token: ') . $e->getMessage();
                        $this->addLog('jwt.create_failed', 'error', [
                            'algorithm' => $algorithm,
                            'error' => $this->shortenMessage($e->getMessage()),
                        ]);
                    }
                }
            }
        }

        if ($notice !== '') {
            $this->message($notice);
        }
        if ($error !== '') {
            $this->error($error);
        }

        $cacheClass = is_object($cache) ? get_class($cache) : 'Cache unavailable';
        $diagnosticsPayload = $this->buildDiagnosticsPayload($form, $tokenForge);
        $diagnostics = $this->buildDiagnostics($diagnosticsPayload, $activeTabUrl);

        return $this->renderAdminUi($tokenForge, $cacheClass, $resultJwt, [
            'algorithm' => $form['algorithm'],
            'key_id' => $form['key_id'],
            'cache_key' => $form['cache_key'],
            'ttl' => $form['ttl'],
            'private_key_path' => $form['private_key_path'],
            'private_key' => $form['private_key'],
            'secret' => $form['secret'],
            'apple_team_id' => (string)($applePreset['apple_team_id'] ?? ''),
            'apple_service_id' => (string)($applePreset['apple_service_id'] ?? ''),
            'apple_key_id' => (string)($applePreset['apple_key_id'] ?? ''),
            'apple_private_key_path' => (string)($applePreset['apple_private_key_path'] ?? ''),
            'headers_json' => $form['headers_json'],
            'payload_json' => $form['payload_json'],
            'private_key_for_validation' => (string)$form['private_key'],
            'error' => $error,
            'result_jwt' => $resultJwt,
            'parsed_jwt' => $parsedJwt,
            'preset_profile_json' => $this->presetProfileJson($applePreset, $form),
            'activity_log' => $this->getLog(),
            'active_tab' => $activeTab,
            'active_tab_action_url' => $activeTabUrl,
            'diagnostics' => $diagnostics,
            'csrf_input' => $csrf->renderInput(),
            'admin_defaults' => $adminDefaults,
        ]);
    }

    protected function resolveAdminTab(string $tab): string {
        $tab = strtolower(trim($tab));
        $allowed = [
            'dashboard',
            'quick-presets',
            'apple-preset',
            'apple-profile',
            'generate-jwt',
            'diagnostics',
            'cache',
            'activity-log',
        ];
        return in_array($tab, $allowed, true) ? $tab : 'dashboard';
    }

    protected function buildDiagnosticsPayload(array $f, ?TokenForge $tokenForge): array {
        $openssl = extension_loaded('openssl');
        $cache = $this->wire('cache');
        $config = $this->wire('config');
        $cachePath = is_object($config) && !empty($config->paths->cache) ? $config->paths->cache : sys_get_temp_dir() . '/';
        $profilePath = $cachePath . self::APPLE_PRESET_PROFILE_FILE;
        $storedProfilePath = $this->getStoredProfilePath();
        $keyPath = trim((string)($f['private_key_path'] ?? ''));
        $algorithm = strtoupper((string)($f['algorithm'] ?? 'HS256'));
        $checks = [];

        $checks[] = [
            'label' => $this->_('Superuser gate'),
            'status' => 'ok',
            'details' => $this->_('Current user is superuser.'),
        ];
        $checks[] = [
            'label' => $this->_('OpenSSL extension'),
            'status' => $openssl ? 'ok' : 'error',
            'details' => $openssl ? (defined('OPENSSL_VERSION_TEXT') ? OPENSSL_VERSION_TEXT : 'installed') : $this->_('OpenSSL extension is missing.'),
        ];
        $checks[] = [
            'label' => $this->_('Cache backend'),
            'status' => is_object($cache) ? 'ok' : 'error',
            'details' => is_object($cache) ? get_class($cache) : $this->_('Cache service is unavailable.'),
        ];
        $checks[] = [
            'label' => $this->_('TokenForge module'),
            'status' => $tokenForge instanceof TokenForge ? 'ok' : 'warning',
            'details' => $tokenForge instanceof TokenForge
                ? sprintf($this->_('Module version %s.'), (string)($tokenForge->getModuleInfo()['version'] ?? 'n/a'))
                : $this->_('TokenForge module is not installed.'),
        ];
        $checks[] = [
            'label' => $this->_('Stored profile path'),
            'status' => is_writable(dirname($storedProfilePath)) ? 'ok' : 'warning',
            'details' => $storedProfilePath,
        ];
        $checks[] = [
            'label' => $this->_('Private key path storage folder writable'),
            'status' => is_writable(dirname($cachePath)) ? 'ok' : 'warning',
            'details' => $this->_('Profile export/import cache path: ') . $cachePath,
        ];
        $checks[] = [
            'label' => $this->_('Profile export file target'),
            'status' => is_writable(dirname($profilePath)) ? 'ok' : 'warning',
            'details' => $profilePath,
        ];

        if (in_array($algorithm, ['RS256', 'ES256'], true)) {
            $resolvedKeyPath = $this->resolvePrivateKeyPath($keyPath);
            if ($keyPath === '') {
                $checks[] = [
                    'label' => $this->_('Private key path'),
                    'status' => 'warning',
                    'details' => $this->_('Algorithm requires private_key or private_key_path; key path is empty.'),
                ];
            } elseif ($resolvedKeyPath === '' || !is_readable($resolvedKeyPath)) {
                $checks[] = [
                    'label' => $this->_('Private key path'),
                    'status' => 'error',
                    'details' => sprintf($this->_('Path is not readable: %s'), $keyPath),
                ];
            } else {
                $checks[] = [
                    'label' => $this->_('Private key path'),
                    'status' => 'ok',
                    'details' => sprintf($this->_('Readable path: %s'), $resolvedKeyPath),
                ];
            }
        } else {
            $checks[] = [
                'label' => $this->_('Private key path'),
                'status' => 'ok',
                'details' => $this->_('HS256 does not require asymmetric key file by default.'),
            ];
        }

        return [
            'generated_at' => gmdate('c'),
            'checks' => $checks,
            'context' => [
                'requested_algorithm' => $algorithm,
                'private_key_path' => $keyPath,
            ],
        ];
    }

    protected function buildDiagnostics(array $payload, string $formActionUrl): string {
        $formAction = $this->h($formActionUrl);
        $diagnosticsJsonRaw = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $diagnosticsJson = $this->h((string)($diagnosticsJsonRaw === false ? '{}' : $diagnosticsJsonRaw));
        $rows = '';
        $checks = $payload['checks'] ?? [];
        $checks = is_array($checks) ? $checks : [];
        foreach ($checks as $check) {
            $status = (string)($check['status'] ?? 'warning');
            $statusClass = $status === 'ok' ? 'uk-label-success' : ($status === 'error' ? 'uk-label-danger' : 'uk-label-warning');
            $label = $this->h($check['label'] ?? 'check');
            $details = $this->h($check['details'] ?? '');
            $rows .= '<tr>'
                . '<td>' . $label . '</td>'
                . '<td><span class="uk-label ' . $statusClass . '">' . $this->h($status) . '</span></td>'
                . '<td>' . $details . '</td>'
                . '</tr>';
        }

        return <<<HTML
<div class="tf-panel tf-table-panel">
    <div class="tf-panel-heading"><h2>{$this->_('Diagnostics')}</h2><p>{$this->_('Environment checks and exportable support payload.')}</p></div>
    <div class="uk-margin-small">
        <button type="button" class="uk-button uk-button-default" data-copy-target="#tf-diagnostics-json">{$this->_('Copy diagnostics JSON')}</button>
        <form method="post" action="{$formAction}" class="uk-margin-small-top uk-display-inline">
            {$this->session->CSRF->renderInput()}
            <input type="hidden" name="action" value="export_diagnostics_file">
            <button class="uk-button uk-button-secondary" type="submit">{$this->_('Export diagnostics as file')}</button>
        </form>
    </div>
    <table class="uk-table uk-table-small uk-table-divider">
        <thead>
            <tr>
                <th>{$this->_('Check')}</th>
                <th>{$this->_('Status')}</th>
                <th>{$this->_('Details')}</th>
            </tr>
        </thead>
        <tbody>{$rows}</tbody>
    </table>
    <textarea id="tf-diagnostics-json" style="display:none;">{$diagnosticsJson}</textarea>
</div>
HTML;
    }

    protected function renderAdminStyles(): string {
        return <<<HTML
<style>
.tf-tokenforge {
    --tf-border: var(--pw-border-color, rgba(0,0,0,.16));
    --tf-text: var(--pw-text-color, #111);
    --tf-muted: var(--pw-muted-color, rgba(0,0,0,.55));
    --tf-surface: var(--pw-blocks-background, #fff);
    --tf-muted-surface: var(--pw-inputs-background, #f8f8f8);
    --tf-page-surface: var(--pw-main-background, #eee);
    --tf-accent: var(--pw-main-color, #eb1d61);
    --tf-accent-contrast: var(--pw-button-color, #fff);
    color: var(--tf-text);
}

body.dark-theme .tf-tokenforge {
    --tf-muted: var(--pw-muted-color, rgba(255,255,255,.6));
    --tf-border: var(--pw-border-color, #444);
    --tf-surface: var(--pw-blocks-background, #0f0f0f);
    --tf-muted-surface: var(--pw-inputs-background, #161616);
    --tf-page-surface: var(--pw-main-background, #222);
}

.tf-tokenforge .uk-table {
    color: var(--tf-text);
}

.tf-tokenforge a.uk-button,
.tf-tokenforge a.uk-button:hover,
.tf-tokenforge a.uk-button:focus {
    text-decoration: none;
}

.tf-tokenforge .tf-admin-nav {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 24px;
}

.tf-tokenforge .tf-admin-nav .uk-subnav {
    margin-bottom: 0;
    margin-left: -13px;
    row-gap: 12px;
}

.tf-tokenforge .tf-admin-nav .uk-subnav > * {
    padding-left: 13px;
}

.tf-tokenforge .tf-admin-nav .uk-subnav-pill > .uk-active > a {
    background: var(--tf-accent);
    color: var(--tf-accent-contrast);
}

.tf-tokenforge .tf-dashboard {
    display: grid;
    grid-template-columns: 200px 1fr;
    gap: 24px;
    align-items: start;
    margin-bottom: 24px;
}

.tf-tokenforge .tf-dashboard-header,
.tf-tokenforge .tf-dashboard-panels,
.tf-tokenforge .tf-index-status {
    grid-column: 1/-1;
}

.tf-tokenforge .tf-dashboard-header {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 18px;
    align-items: end;
}

.tf-tokenforge .tf-dashboard-header p,
.tf-tokenforge .tf-dashboard-panels p,
.tf-tokenforge .tf-panel-heading p {
    margin: 0;
    color: var(--tf-muted);
}

.tf-tokenforge .tf-dashboard-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    justify-content: flex-end;
}

.tf-tokenforge .tf-score-widget {
    padding: 20px;
    background: var(--tf-surface);
    border: 1px solid var(--tf-border);
    text-align: center;
}

.tf-tokenforge .tf-score-shell {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 126px;
    height: 58px;
    margin: 0 auto 12px;
    overflow: visible;
    border: 3px solid var(--tf-text);
    border-radius: 7px;
    background: var(--tf-muted-surface);
}

.tf-tokenforge .tf-score-shell::after {
    content: "";
    position: absolute;
    right: -11px;
    width: 8px;
    height: 22px;
    border-radius: 0 4px 4px 0;
    background: var(--tf-text);
}

.tf-tokenforge .tf-score-shell span:first-child {
    position: absolute;
    inset: 4px auto 4px 4px;
    width: calc(100% - 8px);
    max-width: calc(100% - 8px);
    border-radius: 4px;
    background: var(--tf-accent);
    opacity: .26;
}

.tf-tokenforge .tf-score-shell strong {
    position: relative;
    z-index: 1;
    font-size: 22px;
    font-weight: 700;
    color: var(--tf-text);
}

.tf-tokenforge .tf-score-widget p {
    margin: 0;
    color: var(--tf-muted);
}

.tf-tokenforge .tf-quick-stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
}

.tf-tokenforge .tf-stat-card {
    display: grid;
    gap: 5px;
    align-content: center;
    min-height: 118px;
    padding: 16px;
    background: var(--tf-surface);
    border: 1px solid var(--tf-border);
    text-align: center;
    color: var(--tf-text);
    text-decoration: none;
}

.tf-tokenforge .tf-stat-card:hover,
.tf-tokenforge .tf-stat-card:focus {
    text-decoration: none;
    border-color: var(--tf-accent);
}

.tf-tokenforge .tf-stat-value {
    display: block;
    font-size: 26px;
    font-weight: 700;
    color: var(--tf-accent);
}

.tf-tokenforge .tf-stat-label {
    display: block;
    margin-top: 4px;
}

.tf-tokenforge .tf-stat-card small,
.tf-tokenforge .tf-index-status {
    color: var(--tf-muted);
}

.tf-tokenforge .tf-index-status {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    align-items: center;
}

.tf-tokenforge .tf-dashboard-panels {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(320px, .8fr);
    gap: 18px;
}

.tf-tokenforge .tf-dashboard-panels section,
.tf-tokenforge .tf-panel,
.tf-tokenforge .tf-form-panel,
.tf-tokenforge .tf-table-panel,
.tf-tokenforge .tf-card {
    padding: 18px;
    background: var(--tf-surface);
    border: 1px solid var(--tf-border);
    color: var(--tf-text);
}

.tf-tokenforge .tf-panel-heading {
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: baseline;
    margin-bottom: 14px;
}

.tf-tokenforge .tf-panel-heading h2,
.tf-tokenforge .tf-panel-heading h3,
.tf-tokenforge .uk-card-title {
    margin: 0;
    color: var(--tf-text);
    font-size: 18px;
    line-height: 1.25;
}

.tf-tokenforge .tf-panel-heading p {
    text-align: right;
}

.tf-tokenforge .tf-dashboard-activity {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px;
    margin-top: 12px;
}

.tf-tokenforge .tf-dashboard-activity a,
.tf-tokenforge .tf-dashboard-activity div {
    padding: 14px;
    background: var(--tf-muted-surface);
    border: 1px solid var(--tf-border);
    text-align: center;
    color: var(--tf-text);
    text-decoration: none;
}

.tf-tokenforge .tf-dashboard-activity strong,
.tf-tokenforge .tf-dashboard-activity span {
    display: block;
}

.tf-tokenforge .tf-dashboard-activity strong {
    color: var(--tf-accent);
    font-size: 24px;
}

.tf-tokenforge .tf-preset-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
}

.tf-tokenforge .tf-reference-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px;
    margin-bottom: 18px;
}

.tf-tokenforge .tf-technical-grid {
    display: grid;
    grid-template-columns: minmax(0, 1.15fr) minmax(280px, .85fr);
    gap: 18px;
    margin-bottom: 18px;
}

.tf-tokenforge .tf-preset-item,
.tf-tokenforge .tf-note,
.tf-tokenforge .tf-reference-card {
    background: var(--tf-muted-surface);
    border: 1px solid var(--tf-border);
    padding: 14px;
}

.tf-tokenforge .tf-preset-item {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    min-width: 0;
}

.tf-tokenforge .tf-preset-item h4 {
    margin: 0 0 8px;
}

.tf-tokenforge .tf-preset-item p {
    margin: 0;
    color: var(--tf-muted);
    font-size: .9rem;
}

.tf-tokenforge .tf-preset-item .uk-button {
    margin-top: 10px;
    white-space: normal;
}

.tf-tokenforge .tf-reference-card h3 {
    margin: 0 0 8px;
    font-size: 16px;
}

.tf-tokenforge .tf-reference-card p,
.tf-tokenforge .tf-reference-card li {
    color: var(--tf-muted);
}

.tf-tokenforge .tf-reference-card ul,
.tf-tokenforge .tf-reference-card ol {
    margin: 8px 0 0;
    padding-left: 20px;
}

.tf-tokenforge .tf-example-table {
    width: 100%;
    margin-top: 8px;
    border-collapse: collapse;
}

.tf-tokenforge .tf-example-table th,
.tf-tokenforge .tf-example-table td {
    padding: 6px 8px;
    border-top: 1px solid var(--tf-border);
    text-align: left;
    vertical-align: top;
    font-size: 13px;
    line-height: 1.35;
}

.tf-tokenforge .tf-example-table th {
    color: var(--tf-muted);
    font-weight: 400;
}

.tf-tokenforge .tf-field-note,
.tf-tokenforge .tf-section-note,
.tf-tokenforge .tf-muted {
    color: var(--tf-muted);
}

.tf-tokenforge .tf-field-note {
    display: block;
    margin-top: 4px;
}

.tf-tokenforge .tf-section-note {
    margin: 6px 0 14px 0;
}

.tf-tokenforge .uk-label {
    border-radius: 999px;
}

.tf-tokenforge textarea,
.tf-tokenforge .uk-input,
.tf-tokenforge .uk-select {
    border-radius: var(--pw-input-radius, 6px);
}

.tf-tokenforge textarea[readonly] {
    background: var(--pw-inputs-background, #f8f8f8);
    color: var(--tf-text);
}

.tf-tokenforge .tf-copy-feedback {
    color: var(--tf-accent);
    margin-left: 8px;
    opacity: 0;
    transition: opacity 140ms ease;
    font-size: .85rem;
}

.tf-tokenforge .tf-copy-feedback.is-visible {
    opacity: 1;
}

.tf-tokenforge .tf-monospaced {
    font-family: var(--pw-font-family-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace);
    font-size: 12px;
    line-height: 1.45;
}

@media (max-width: 959px) {
    .tf-tokenforge .tf-dashboard-header,
    .tf-tokenforge .tf-dashboard-panels {
        grid-template-columns: 1fr;
    }
    .tf-tokenforge .tf-dashboard-actions {
        justify-content: flex-start;
    }
    .tf-tokenforge .tf-quick-stats {
        grid-template-columns: repeat(2, 1fr);
    }
    .tf-tokenforge .tf-preset-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .tf-tokenforge .tf-reference-grid,
    .tf-tokenforge .tf-technical-grid {
        grid-template-columns: 1fr;
    }
}

@media (max-width: 640px) {
    .tf-tokenforge .tf-dashboard {
        grid-template-columns: 1fr;
    }
    .tf-tokenforge .tf-quick-stats,
    .tf-tokenforge .tf-dashboard-activity,
    .tf-tokenforge .tf-preset-grid {
        grid-template-columns: 1fr;
    }
    .tf-tokenforge .tf-panel-heading {
        display: block;
    }
    .tf-tokenforge .tf-panel-heading p {
        text-align: left;
        margin-top: 4px;
    }
}
</style>
HTML;
    }

    protected function presetProfileJson(array $applePreset, array $f): string {
        $payload = [
            'schema' => 'tokenforge.apple-preset-profile',
            'version' => 1,
            'generated_at' => gmdate('c'),
            'apple_team_id' => $applePreset['apple_team_id'] ?? '',
            'apple_service_id' => $applePreset['apple_service_id'] ?? '',
            'apple_key_id' => $applePreset['apple_key_id'] ?? '',
            'apple_private_key_path' => $applePreset['apple_private_key_path'] ?? '',
            'algorithm' => (string)($f['algorithm'] ?? ''),
            'key_id' => (string)($f['key_id'] ?? ''),
            'cache_key' => (string)($f['cache_key'] ?? ''),
            'ttl' => (string)($f['ttl'] ?? ''),
            'private_key_path' => (string)($f['private_key_path'] ?? ''),
            'headers_json' => (string)($f['headers_json'] ?? ''),
            'payload_json' => (string)($f['payload_json'] ?? ''),
        ];

        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        return $json === false ? '{}' : $json;
    }

    protected function adminPageUrl(): string {
        $page = $this->wire('page');
        if (is_object($page) && isset($page->url) && (string)$page->url !== '') {
            return (string)$page->url;
        }

        $config = $this->wire('config');
        $adminUrl = is_object($config) && isset($config->urls->admin) ? (string)$config->urls->admin : '/admin/';
        return rtrim($adminUrl, '/') . '/setup/token-forge/';
    }

    protected function adminTabUrl(string $tab): string {
        return rtrim($this->adminPageUrl(), '/') . '/?tab=' . rawurlencode($tab);
    }

    protected function resolvePrivateKeyPath(string $path): string {
        $path = trim($path);
        if ($path === '') {
            return '';
        }

        try {
            $config = $this->wire('config');
            if (is_object($config) && !empty($config->paths->root)) {
                $root = (string)$config->paths->root;
            } elseif (is_object($config) && !empty($config->paths->site)) {
                $root = dirname(rtrim((string)$config->paths->site, '/\\')) . '/';
            } else {
                $root = dirname(__DIR__, 3) . '/';
            }
            return (new KeyLoader($root))->resolvePrivateKeyPath($path);
        } catch (\Throwable $e) {
            return '';
        }
    }

    protected function h(mixed $value): string {
        return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    protected function renderAdminUi($tokenForge, string $cacheClass, string $resultJwt, array $f): string {
        $openssl = function_exists('openssl_sign') ? $this->_('Available') : $this->_('Missing');
        $activeTab = (string)($f['active_tab'] ?? 'dashboard');
        $tabActionUrl = $this->h($f['active_tab_action_url'] ?? './');
        $tabDashboardUrl = $this->h($this->adminTabUrl('dashboard'));
        $tabQuickPresetsUrl = $this->h($this->adminTabUrl('quick-presets'));
        $tabApplePresetUrl = $this->h($this->adminTabUrl('apple-preset'));
        $tabAppleProfileUrl = $this->h($this->adminTabUrl('apple-profile'));
        $tabGenerateUrl = $this->h($this->adminTabUrl('generate-jwt'));
        $tabDiagnosticsUrl = $this->h($this->adminTabUrl('diagnostics'));
        $tabCacheUrl = $this->h($this->adminTabUrl('cache'));
        $tabLogUrl = $this->h($this->adminTabUrl('activity-log'));
        $tabDashboardClass = $activeTab === 'dashboard' ? 'uk-active' : '';
        $tabQuickPresetsClass = $activeTab === 'quick-presets' ? 'uk-active' : '';
        $tabApplePresetClass = $activeTab === 'apple-preset' ? 'uk-active' : '';
        $tabAppleProfileClass = $activeTab === 'apple-profile' ? 'uk-active' : '';
        $tabGenerateClass = $activeTab === 'generate-jwt' ? 'uk-active' : '';
        $tabDiagnosticsClass = $activeTab === 'diagnostics' ? 'uk-active' : '';
        $tabCacheClass = $activeTab === 'cache' ? 'uk-active' : '';
        $tabLogClass = $activeTab === 'activity-log' ? 'uk-active' : '';
        $cacheClass = $this->h($cacheClass);
        $algorithm = $this->h($f['algorithm'] ?? '');
        $keyId = $this->h($f['key_id'] ?? '');
        $cacheKey = $this->h($f['cache_key'] ?? '');
        $ttl = $this->h($f['ttl'] ?? '');
        $privateKeyPath = $this->h($f['private_key_path'] ?? '');
        $privateKey = $this->h($f['private_key'] ?? '');
        $privateKeyForValidation = $this->h($f['private_key_for_validation'] ?? '');
        $secret = $this->h($f['secret'] ?? '');
        $appleTeamId = $this->h($f['apple_team_id'] ?? '');
        $appleServiceId = $this->h($f['apple_service_id'] ?? '');
        $appleKeyId = $this->h($f['apple_key_id'] ?? '');
        $applePrivateKeyPath = $this->h($f['apple_private_key_path'] ?? '');
        $headersJson = $this->h($f['headers_json'] ?? '');
        $payloadJson = $this->h($f['payload_json'] ?? '');
        $presetProfileJson = $this->h($f['preset_profile_json'] ?? '');
        $adminDefaults = is_array($f['admin_defaults'] ?? null) ? $f['admin_defaults'] : [];
        $defaultTtl = (string)max(60, (int)($adminDefaults['default_ttl'] ?? 3300));
        $defaultPrivateKeyBasePathRaw = rtrim(trim((string)($adminDefaults['private_key_base_path'] ?? '/site/assets/private/')), '/\\') . '/';
        $defaultPrivateKeyBasePath = $this->h($defaultPrivateKeyBasePathRaw);
        $defaultCacheKeyPrefixRaw = trim((string)($adminDefaults['cache_key_prefix'] ?? 'provider_'));
        $defaultCacheKeyPrefix = $this->h($defaultCacheKeyPrefixRaw);
        $defaultCacheKeyPlaceholder = $this->h(($defaultCacheKeyPrefixRaw !== '' ? $defaultCacheKeyPrefixRaw : 'provider_') . 'access_token');
        $defaultAppleKeyPath = $this->h($defaultPrivateKeyBasePathRaw . 'AuthKey_APPLEKEY123.p8');
        $defaultGenericKeyPath = $this->h($defaultPrivateKeyBasePathRaw . 'AuthKey_XXXXX.p8');
        $showOfficialDocs = !empty($adminDefaults['show_official_docs']);
        $officialDocsHtml = $showOfficialDocs ? <<<HTML
                <div class="tf-reference-card">
                    <h3>{$this->_('Official Apple documentation')}</h3>
                    <ul>
                        <li><a href="https://developer.apple.com/documentation/weatherkitrestapi/request-authentication-for-weatherkit-rest-api" target="_blank" rel="noopener">WeatherKit REST API authentication</a></li>
                        <li><a href="https://developer.apple.com/documentation/applemapsserverapi/creating-and-using-tokens-with-maps-server-api" target="_blank" rel="noopener">Apple Maps Server API tokens</a></li>
                        <li><a href="https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns" target="_blank" rel="noopener">APNs token-based connection</a></li>
                        <li><a href="https://developer.apple.com/documentation/appstoreconnectapi/generating-tokens-for-api-requests" target="_blank" rel="noopener">App Store Connect API JWTs</a></li>
                        <li><a href="https://developer.apple.com/help/account/keys/create-a-private-key/" target="_blank" rel="noopener">Create an Apple private key</a></li>
                    </ul>
                </div>
HTML : '';

        $resultHtml = $resultJwt === '' ? '<div class="uk-alert uk-alert-warning tf-note">' . $this->_('Generate token to see live result.') . '</div>'
            : '<textarea class="uk-textarea tf-monospaced" style="min-height:160px;white-space:pre-wrap;" readonly>'
            . $this->h($resultJwt) . '</textarea>';

        return <<<HTML
{$this->renderAdminStyles()}
<div class="tf-tokenforge ProcessTokenForge">
<div class="tf-admin-nav">
    <ul class="uk-subnav uk-subnav-pill uk-flex uk-flex-wrap">
        <li class="{$tabDashboardClass}"><a href="{$tabDashboardUrl}">{$this->_('Dashboard')}</a></li>
        <li class="{$tabQuickPresetsClass}"><a href="{$tabQuickPresetsUrl}">{$this->_('Presets')}</a></li>
        <li class="{$tabApplePresetClass}"><a href="{$tabApplePresetUrl}">{$this->_('Apple')}</a></li>
        <li class="{$tabAppleProfileClass}"><a href="{$tabAppleProfileUrl}">{$this->_('Apple Profiles')}</a></li>
        <li class="{$tabGenerateClass}"><a href="{$tabGenerateUrl}">{$this->_('Generator')}</a></li>
        <li class="{$tabDiagnosticsClass}"><a href="{$tabDiagnosticsUrl}">{$this->_('Diagnostics')}</a></li>
        <li class="{$tabCacheClass}"><a href="{$tabCacheUrl}">{$this->_('Cache')}</a></li>
        <li class="{$tabLogClass}"><a href="{$tabLogUrl}">{$this->_('Activity')}</a></li>
    </ul>
    <a href="{$tabGenerateUrl}" class="uk-button uk-button-secondary">{$this->_('Generate JWT')}</a>
</div>

<ul class="uk-switcher uk-margin-remove">
    <li class="{$tabDashboardClass}">
        <div class="tf-dashboard">
            <div class="tf-dashboard-header">
                <div><p>{$this->_('A compact overview of signing support, cache readiness, provider playbooks and the fastest next actions for token integrations.')}</p></div>
                <div class="tf-dashboard-actions">
                    <a class="uk-button uk-button-default" href="{$tabQuickPresetsUrl}">{$this->_('Open Presets')}</a>
                    <a class="uk-button uk-button-secondary" href="{$tabGenerateUrl}">{$this->_('Generate Token')}</a>
                </div>
            </div>
            <div class="tf-score-widget">
                <div class="tf-score-shell"><span></span><strong>JWT</strong></div>
                <p class="uk-text-small">{$this->_('Signed token toolkit')}</p>
                <a href="{$tabDiagnosticsUrl}">{$this->_('Review diagnostics')}</a>
            </div>
            <div class="tf-quick-stats">
                <a class="tf-stat-card" href="{$tabDiagnosticsUrl}"><span class="tf-stat-value">{$openssl}</span><span class="tf-stat-label">{$this->_('OpenSSL')}</span><small>RS256 · ES256</small></a>
                <a class="tf-stat-card" href="{$tabCacheUrl}"><span class="tf-stat-value">{$this->_('Ready')}</span><span class="tf-stat-label">{$this->_('Cache')}</span><small>{$cacheClass}</small></a>
                <a class="tf-stat-card" href="{$tabQuickPresetsUrl}"><span class="tf-stat-value">6</span><span class="tf-stat-label">{$this->_('Presets')}</span><small>Apple · Android · Samsung · Generic</small></a>
            </div>
            <div class="tf-index-status">
                <span>{$this->_('Algorithms: HS256 shared secret, RS256 RSA private key, ES256 EC P-256 private key.')}</span>
                <a class="uk-button uk-button-default" href="{$tabApplePresetUrl}">{$this->_('Apple setup')}</a>
            </div>
            <div class="tf-dashboard-panels">
                <section>
                    <div class="tf-panel-heading"><h3>{$this->_('Provider playbooks')}</h3><p>{$this->_('Choose the closest integration family before editing claims.')}</p></div>
                    <div class="tf-dashboard-activity">
                        <a href="{$tabApplePresetUrl}"><strong>ES256</strong><span>{$this->_('Apple WeatherKit')}</span></a>
                        <a href="{$tabQuickPresetsUrl}"><strong>RS256</strong><span>{$this->_('Android / Firebase')}</span></a>
                        <a href="{$tabQuickPresetsUrl}"><strong>RS256</strong><span>{$this->_('Samsung services')}</span></a>
                        <a href="{$tabGenerateUrl}"><strong>JWT</strong><span>{$this->_('Generic APIs')}</span></a>
                    </div>
                </section>
                <section>
                    <div class="tf-panel-heading"><h3>{$this->_('Rules')}</h3><p>{$this->_('Small defaults that prevent token pain later.')}</p></div>
                    <div class="tf-dashboard-activity">
                        <div><strong>exp</strong><span>{$this->_('Keep short-lived')}</span></div>
                        <div><strong>kid</strong><span>{$this->_('Match provider key id')}</span></div>
                        <div><strong>/site</strong><span>{$this->_('Prefer key path')}</span></div>
                        <div><strong>cache</strong><span>{$this->_('Reuse until expiry')}</span></div>
                    </div>
                </section>
            </div>
        </div>
    </li>
    <li class="{$tabQuickPresetsClass}">
        <div class="tf-panel tf-form-panel">
            <div class="tf-panel-heading"><h2>{$this->_('Quick presets')}</h2><p>{$this->_('Start from the provider shape closest to your integration.')}</p></div>
            <p class="tf-section-note">{$this->_('Choose the closest integration shape. Quick presets include demo signing material so Generate works immediately; replace demo identifiers, audience values and keys before using a real provider API.')}</p>
            <div class="tf-preset-grid">
                <div class="tf-preset-item">
                    <h4 class="uk-text-small uk-margin-small-bottom">{$this->_('Apple WeatherKit')}</h4>
                    <p>{$this->_('ES256 with issuer/team ID, service identifier, key ID and a demo P-256 key. Best starting point for WeatherKit, Maps, APNs-style and other Apple service tokens.')}</p>
                    <button type="button" class="uk-button uk-button-default" data-tf-preset-id="apple_weatherkit">{$this->_('Apply Apple preset')}</button>
                </div>
                <div class="tf-preset-item">
                    <h4 class="uk-text-small uk-margin-small-bottom">{$this->_('Android / Firebase')}</h4>
                    <p>{$this->_('RS256 service-account style JWT assertion with a demo RSA key for Google/Firebase-style OAuth flows before exchanging for an access token.')}</p>
                    <button type="button" class="uk-button uk-button-default" data-tf-preset-id="android_firebase">{$this->_('Apply Android preset')}</button>
                </div>
                <div class="tf-preset-item">
                    <h4 class="uk-text-small uk-margin-small-bottom">{$this->_('Samsung services')}</h4>
                    <p>{$this->_('Generic RS256 bearer/client assertion starter with a demo RSA key for Samsung or device-platform APIs that document JWT-based server authentication.')}</p>
                    <button type="button" class="uk-button uk-button-default" data-tf-preset-id="samsung_services">{$this->_('Apply Samsung preset')}</button>
                </div>
                <div class="tf-preset-item">
                    <h4 class="uk-text-small uk-margin-small-bottom">{$this->_('Generic HS256')}</h4>
                    <p>{$this->_('Shared-secret JWT for internal APIs, simple vendor integrations and local testing where both sides know the same secret.')}</p>
                    <button type="button" class="uk-button uk-button-default" data-tf-preset-id="hs256">{$this->_('Apply HS256 preset')}</button>
                </div>
                <div class="tf-preset-item">
                    <h4 class="uk-text-small uk-margin-small-bottom">{$this->_('Generic ES256')}</h4>
                    <p>{$this->_('ECDSA P-256 JWT with a demo EC key for providers that require ES256 but are not Apple. Useful when docs mention EC private key or P-256.')}</p>
                    <button type="button" class="uk-button uk-button-default" data-tf-preset-id="es256">{$this->_('Apply ES256 preset')}</button>
                </div>
                <div class="tf-preset-item">
                    <h4 class="uk-text-small uk-margin-small-bottom">{$this->_('Generic RS256')}</h4>
                    <p>{$this->_('RSA private key JWT with a demo RSA key for enterprise APIs, OAuth client assertions and integrations that publish a matching public key.')}</p>
                    <button type="button" class="uk-button uk-button-default" data-tf-preset-id="rs256">{$this->_('Apply RS256 preset')}</button>
                </div>
            </div>
        </div>
    </li>
    <li class="{$tabApplePresetClass}">
        <div class="tf-panel tf-form-panel">
            <div class="tf-panel-heading"><h2>{$this->_('Apple service token preset')}</h2><p>{$this->_('Prepare ES256 JWT claims for Apple developer services.')}</p></div>
            <p class="tf-section-note">{$this->_('Use this when an Apple service asks your server to sign a developer token, provider token, Maps token or API token with an Apple .p8 private key. TokenForge does not upload this key anywhere; it only reads it locally when generating ES256 JWTs.')}</p>
            <div class="tf-technical-grid">
                <form method="post" action="{$tabActionUrl}">
                    {$f['csrf_input']}
                    <input type="hidden" name="action" value="preset_apple">
                    <div class="uk-grid-small uk-child-width-1-2@s uk-grid tf-form-grid" uk-grid>
                        <div>
                            <label>{$this->_('Issuer / Team ID')}</label>
                            <input class="uk-input" type="text" name="apple_team_id" value="{$appleTeamId}" placeholder="TEAMID">
                            <span class="tf-field-note">{$this->_('Usually Apple Team ID. For App Store Connect APIs this may be Issuer ID. TokenForge places it into payload iss.')}</span>
                        </div>
                        <div>
                            <label>{$this->_('Subject / Service identifier')}</label>
                            <input class="uk-input" type="text" name="apple_service_id" value="{$appleServiceId}" placeholder="com.example.weather">
                            <span class="tf-field-note">{$this->_('WeatherKit Services ID, Maps ID, bundle ID, client ID, or another Apple service identifier when the token shape requires sub/id.')}</span>
                        </div>
                        <div>
                            <label>{$this->_('Key ID / kid')}</label>
                            <input class="uk-input" type="text" name="apple_key_id" value="{$appleKeyId}" placeholder="APPLEKEY123">
                            <span class="tf-field-note">{$this->_('Shown next to the Apple private key after creation. TokenForge sends it as the JWT kid header.')}</span>
                        </div>
                        <div>
                            <label>{$this->_('Private key path')}</label>
                            <input class="uk-input" type="text" name="apple_private_key_path" value="{$applePrivateKeyPath}" placeholder="{$defaultAppleKeyPath}">
                            <span class="tf-field-note">{$this->_('Recommended private folder:')} {$defaultPrivateKeyBasePath}{$this->_(' with file permissions readable by PHP, not web-public.')}</span>
                        </div>
                    </div>
                    <button class="uk-button uk-button-default uk-margin-top" type="submit">{$this->_('Build ES256 preset')}</button>
                </form>
                <div class="tf-reference-card">
                    <h3>{$this->_('Where to get the values')}</h3>
                    <ol>
                        <li>{$this->_('Team ID: Apple Developer Account membership page, or the team selector in Certificates, Identifiers & Profiles.')}</li>
                        <li>{$this->_('Service / Maps / Bundle identifier: Identifiers section. For WeatherKit create a Services ID; for Maps create a Maps ID; for APNs use the app bundle ID in the APNs request path, not always in the JWT.')}</li>
                        <li>{$this->_('Key ID and .p8: Keys section. Create a key with the required capability enabled, download the .p8 once, then store it outside the web root or under')} {$defaultPrivateKeyBasePath}</li>
                        <li>{$this->_('Issuer ID: App Store Connect API Keys page. App Store Connect uses issuer ID instead of Team ID in the iss claim.')}</li>
                    </ol>
                </div>
            </div>
            <div class="tf-reference-grid">
                <div class="tf-reference-card">
                    <h3>{$this->_('Apple service examples')}</h3>
                    <table class="tf-example-table">
                        <thead><tr><th>{$this->_('Service')}</th><th>{$this->_('Typical identifiers')}</th><th>{$this->_('Use')}</th></tr></thead>
                        <tbody>
                            <tr><td>WeatherKit REST API</td><td>Team ID, Services ID, Key ID, .p8</td><td>{$this->_('Weather requests.')}</td></tr>
                            <tr><td>MapKit JS / Maps Server API</td><td>Team ID, Maps ID, Key ID, .p8</td><td>{$this->_('Map and route services.')}</td></tr>
                            <tr><td>APNs</td><td>Team ID, APNs Key ID, .p8</td><td>{$this->_('Push provider token.')}</td></tr>
                            <tr><td>App Store Connect / Server API</td><td>Issuer ID, Key ID, .p8</td><td>{$this->_('Store operations APIs.')}</td></tr>
                            <tr><td>MusicKit / DeviceCheck</td><td>Team ID, Key ID, .p8</td><td>{$this->_('Developer tokens.')}</td></tr>
                        </tbody>
                    </table>
                </div>
{$officialDocsHtml}
            </div>
        </div>
    </li>
    <li class="{$tabAppleProfileClass}">
        <div class="tf-panel tf-form-panel">
            <div class="tf-panel-heading"><h2>{$this->_('Apple preset profiles')}</h2><p>{$this->_('Import or export reusable non-secret setup values.')}</p></div>
            <p class="tf-section-note">{$this->_('Profiles are convenience JSON files for non-secret Apple values and generator settings. They may include paths, ids and JSON claims, but should not include private key contents or shared secrets.')}</p>
            <div class="uk-grid-small uk-child-width-1-2@s tf-form-grid" uk-grid>
                <div class="uk-width-1-1@s">
                    <h4 class="uk-text-small uk-margin-small-bottom">{$this->_('Import profile')}</h4>
                        <form method="post" action="{$tabActionUrl}" enctype="multipart/form-data">
                        {$f['csrf_input']}
                        <input type="hidden" name="action" value="import_preset_profile">
                        <label>{$this->_('Profile JSON')}</label>
                        <textarea class="uk-textarea uk-margin-small" name="preset_profile_json" rows="8" placeholder='{"schema":"tokenforge.apple-preset-profile","apple_team_id":"..."}'>{$presetProfileJson}</textarea>
                        <span class="tf-field-note">{$this->_('Paste a TokenForge profile JSON export here, or upload the file below. Invalid JSON is rejected before saving.')}</span>
                        <div class="uk-margin-small">
                            <input class="uk-input" type="file" name="preset_profile_file" accept="application/json">
                        </div>
                        <button class="uk-button uk-button-primary" type="submit">{$this->_('Import profile')}</button>
                    </form>
                </div>
                <div class="uk-width-1-1@s">
                    <h4 class="uk-text-small uk-margin-small-bottom">{$this->_('Export profile')}</h4>
                    <div class="uk-margin-small">
                        <p class="uk-margin-small">{$this->_('Use current session profile or download as JSON file.')}</p>
                        <p>
                            <button type="button" class="uk-button uk-button-default" data-copy-target="#tf-preset-profile-json">{$this->_('Copy profile JSON')}</button>
                            <span class="tf-copy-feedback">{$this->_('Copied')}</span>
                        </p>
                        <form method="post" action="{$tabActionUrl}">
                            {$f['csrf_input']}
                            <input type="hidden" name="action" value="export_preset_profile_file">
                            <button class="uk-button uk-button-secondary" type="submit">{$this->_('Export profile as file')}</button>
                        </form>
                    </div>
                    <label>{$this->_('Current profile JSON')}</label>
                    <textarea id="tf-preset-profile-json" class="uk-textarea" rows="8" readonly>{$presetProfileJson}</textarea>
                    <span class="tf-field-note">{$this->_('This export is meant for reusing setup on another local ProcessWire installation. Review it before sharing.')}</span>
                </div>
            </div>
        </div>
    </li>
    <li class="{$tabGenerateClass}">
        <div class="tf-panel tf-form-panel">
            <div class="tf-panel-heading"><h2>{$this->_('Generate JWT')}</h2><p>{$this->_('Create and inspect a signed token.')}</p></div>
            <p class="tf-section-note">{$this->_('This form creates a signed JWT immediately. Use presets first when possible, then adjust claims to match the target API documentation. Required provider values usually live in the API console under keys, credentials, service accounts or app identifiers.')}</p>
            <form method="post" action="{$tabGenerateUrl}" data-tf-generate-form>
                {$f['csrf_input']}
                <input type="hidden" name="action" value="generate">
                <div class="uk-grid-small uk-child-width-1-2@s uk-grid tf-form-grid" uk-grid>
                    <div>
                        <label>{$this->_('Algorithm')}</label>
                        <select class="uk-select" name="algorithm" data-tf-algorithm>
                            <option value="HS256"{$this->selected((string)($f['algorithm'] ?? ''),'HS256')}>HS256</option>
                            <option value="RS256"{$this->selected((string)($f['algorithm'] ?? ''),'RS256')}>RS256</option>
                            <option value="ES256"{$this->selected((string)($f['algorithm'] ?? ''),'ES256')}>ES256</option>
                        </select>
                        <span class="tf-field-note">{$this->_('HS256 uses a shared secret. RS256 uses an RSA private key. ES256 uses an EC P-256 private key, including Apple .p8 keys.')}</span>
                    </div>
                    <div>
                        <label>{$this->_('Cache key (optional)')}</label>
                        <input class="uk-input" type="text" name="cache_key" value="{$cacheKey}" placeholder="{$defaultCacheKeyPlaceholder}">
                        <span class="tf-field-note">{$this->_('When set, TokenForge stores and reuses a still-valid token for this logical integration. Changing claims or key options creates a fresh cached entry.')}</span>
                    </div>
                    <div>
                        <label>{$this->_('TTL (cached only)')}</label>
                        <input class="uk-input" type="number" name="ttl" value="{$ttl}">
                        <span class="tf-field-note">{$this->_('Seconds to keep cached token. Keep this lower than exp. Current module default:')} {$defaultTtl}{$this->_(' seconds.')}</span>
                    </div>
                    <div>
                        <label>{$this->_('Key ID / kid')}</label>
                        <input class="uk-input" type="text" name="key_id" value="{$keyId}">
                        <span class="tf-field-note">{$this->_('Optional JWT header kid. Many providers use it to find the public key matching your private key.')}</span>
                    </div>
                    <div data-tf-field="requires-secret">
                        <label>{$this->_('Shared secret')}</label>
                        <input class="uk-input" type="text" name="secret" value="{$secret}" placeholder="{$this->_('for HS256')}">
                        <span class="tf-field-note">{$this->_('Only for HS256. Treat it like a password; it signs and verifies the token.')}</span>
                    </div>
                    <div data-tf-field="requires-key">
                        <label>{$this->_('Private key path')}</label>
                        <input class="uk-input" type="text" name="private_key_path" value="{$privateKeyPath}" placeholder="{$defaultGenericKeyPath}">
                        <span class="tf-field-note">{$this->_('Recommended for RS256/ES256. Use an absolute path or /site/... path readable by PHP.')}</span>
                    </div>
                    <div class="uk-width-1-1" data-tf-field="requires-key">
                        <label>{$this->_('Private key (optional inline)')}</label>
                        <textarea class="uk-textarea" name="private_key" rows="3" placeholder="-----BEGIN PRIVATE KEY-----">{$privateKey}</textarea>
                        <span class="tf-field-note">{$this->_('Use only for temporary testing. Inline keys can remain in browser/session history; private_key_path is safer.')}</span>
                    </div>
                    <div class="uk-width-1-1">
                        <label>{$this->_('Headers JSON')}</label>
                        <textarea class="uk-textarea" name="headers_json" rows="3">{$headersJson}</textarea>
                        <span class="tf-field-note">{$this->_('Extra protected header values. TokenForge adds alg and typ automatically, and adds kid when Key ID is set.')}</span>
                    </div>
                    <div class="uk-width-1-1">
                        <label>{$this->_('Payload JSON')}</label>
                        <textarea class="uk-textarea" name="payload_json" rows="5">{$payloadJson}</textarea>
                        <span class="tf-field-note">{$this->_('Claims sent to the provider. Common fields: iss, sub, aud, scope, iat, exp, nbf. Keep exp short for server-to-server credentials.')}</span>
                    </div>
                </div>
                <button class="uk-button uk-button-primary uk-margin-top" type="submit">{$this->_('Generate')}</button>
            </form>
            <form method="post" action="{$tabGenerateUrl}" class="uk-margin-small-top">
                {$f['csrf_input']}
                <input type="hidden" name="action" value="validate_private_key">
                <input type="hidden" name="algorithm" value="{$algorithm}">
                <input type="hidden" name="private_key_path" value="{$privateKeyPath}">
                <input type="hidden" name="private_key" value="{$privateKeyForValidation}">
                <button class="uk-button uk-button-default" type="submit">{$this->_('Validate private key')}</button>
            </form>
        </div>
        <div class="tf-panel tf-table-panel uk-margin-top">
            <div class="tf-panel-heading"><h2>{$this->_('Result')}</h2><p>{$this->_('Generated token and decoded parts appear here.')}</p></div>
            {$resultHtml}
            {$this->renderParsedJwt($f['parsed_jwt'] ?? null, !empty($f['result_jwt']))}
        </div>
    </li>
    <li class="{$tabDiagnosticsClass}">
        {$f['diagnostics']}
    </li>
    <li class="{$tabCacheClass}">
        <div class="tf-panel tf-form-panel">
            <div class="tf-panel-heading"><h2>{$this->_('Clear cached token')}</h2><p>{$this->_('Remove a cached token by logical cache key.')}</p></div>
            <form method="post" action="{$tabActionUrl}">
                {$f['csrf_input']}
                <input type="hidden" name="action" value="clear">
                <div class="uk-width-1-2@s">
                    <label>{$this->_('Cache key')}</label>
                    <input class="uk-input" type="text" name="cache_key" value="" placeholder="{$defaultCacheKeyPlaceholder}">
                </div>
                <button class="uk-button uk-button-danger uk-margin-top" type="submit">{$this->_('Clear')}</button>
                <p class="uk-text-meta uk-margin-small-top">{$this->_('Cached JWT entries are fingerprinted by cache key and token options.')}</p>
            </form>
        </div>
    </li>
    <li class="{$tabLogClass}">
        {$this->renderActivityLog($f['activity_log'] ?? [], $tabActionUrl)}
    </li>
</ul>
{$this->renderCopyScript($defaultTtl, $defaultPrivateKeyBasePathRaw, $defaultCacheKeyPrefixRaw, $tabGenerateUrl)}
</div>
HTML;
    }

    protected function renderParsedJwt(?array $parsed, bool $hasToken): string {
        if (!is_array($parsed)) {
            return '';
        }

        $header = isset($parsed['header_pretty']) ? $parsed['header_pretty'] : '{}';
        $payload = isset($parsed['payload_pretty']) ? $parsed['payload_pretty'] : '{}';
        $sig = $this->h($parsed['signature'] ?? '');
        $fullToken = $this->h($parsed['token'] ?? '');
        $partsJson = $this->h($parsed['parts_json'] ?? '{}');
        $size = isset($parsed['size']) ? (int)$parsed['size'] : 0;
        $copyWrap = '';
        if ($hasToken) {
            $copyWrap = <<<HTML
<div class="uk-margin-small-top">
    <button type="button" class="uk-button uk-button-default" data-copy-target="#tf-jwt-full">{$this->_('Copy token')}</button>
    <button type="button" class="uk-button uk-button-default" data-copy-target="#tf-jwt-parts-json">{$this->_('Copy JWT parts JSON')}</button>
    <button type="button" class="uk-button uk-button-default" data-copy-target="#tf-jwt-header">{$this->_('Copy header')}</button>
    <button type="button" class="uk-button uk-button-default" data-copy-target="#tf-jwt-payload">{$this->_('Copy payload')}</button>
    <button type="button" class="uk-button uk-button-default" data-copy-target="#tf-jwt-signature">{$this->_('Copy signature')}</button>
    <span class="tf-copy-feedback">{$this->_('Copied')}</span>
</div>
HTML;
        }

        return <<<HTML
<div class="uk-grid-small uk-child-width-1-2@s uk-grid uk-margin-small-top" uk-grid>
    <div>
        <h4 class="uk-text-small uk-margin-small-bottom">{$this->_('Header')}</h4>
        <textarea id="tf-jwt-header" class="uk-textarea tf-monospaced" style="min-height:120px;white-space:pre-wrap;" readonly>{$header}</textarea>
    </div>
    <div>
        <h4 class="uk-text-small uk-margin-small-bottom">{$this->_('Payload')}</h4>
        <textarea id="tf-jwt-payload" class="uk-textarea tf-monospaced" style="min-height:120px;white-space:pre-wrap;" readonly>{$payload}</textarea>
    </div>
    <div class="uk-width-1-1">
        <h4 class="uk-text-small uk-margin-small-bottom">{$this->_('Signature')} ({$size} {$this->_('chars')})</h4>
        <textarea id="tf-jwt-signature" class="uk-textarea tf-monospaced" style="min-height:60px;white-space:pre-wrap;" readonly>{$sig}</textarea>
    </div>
    <div class="uk-width-1-1 uk-margin-small-top">
        <h4 class="uk-text-small uk-margin-small-bottom">{$this->_('Token')}</h4>
            <textarea id="tf-jwt-full" style="min-height:80px;white-space:pre-wrap;" class="uk-textarea tf-monospaced" readonly>{$fullToken}</textarea>
        </div>
    <div class="uk-width-1-1">
        <h4 class="uk-text-small uk-margin-small-bottom">{$this->_('JWT parts JSON')}</h4>
            <textarea id="tf-jwt-parts-json" style="display:none;">{$partsJson}</textarea>
    </div>
    {$copyWrap}
</div>
HTML;
    }

    protected function parseJwt(string $jwt): ?array {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return null;
        }

        $headerRaw = $this->base64UrlDecode($parts[0]);
        $payloadRaw = $this->base64UrlDecode($parts[1]);
        $signatureRaw = trim($parts[2]);

        $header = json_decode($headerRaw ?: '{}', true);
        $payload = json_decode($payloadRaw ?: '{}', true);

        return [
            'size' => strlen($jwt),
            'header_json' => is_array($header) ? $header : null,
            'payload_json' => is_array($payload) ? $payload : null,
            'header_pretty' => $this->prettyJson($header),
            'payload_pretty' => $this->prettyJson($payload),
            'signature' => $signatureRaw,
            'token' => $jwt,
            'parts_json' => is_array($header) && is_array($payload)
                ? $this->jsonForCopy([
                    'header' => $header,
                    'payload' => $payload,
                ])
                : '{}',
        ];
    }

    protected function base64UrlDecode(string $value): string {
        $value = strtr($value, '-_', '+/');
        $mod = strlen($value) % 4;
        if ($mod) $value .= str_repeat('=', 4 - $mod);
        $decoded = base64_decode($value, true);
        return $decoded === false ? '' : $decoded;
    }

    protected function prettyJson($data): string {
        if (!is_array($data)) {
            return '{}';
        }
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            return '{}';
        }
        return $this->h($json);
    }

    protected function jsonForCopy($data): string {
        if (!is_array($data)) {
            return '{}';
        }
        $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        return $json === false ? '{}' : $json;
    }

    protected function checkRateLimit(string $action): bool {
        if (!in_array($action, ['preset_apple', 'import_preset_profile', 'export_preset_profile_file', 'export_diagnostics_file', 'validate_private_key', 'generate', 'clear', 'clear_log'], true)) {
            return true;
        }

        $window = self::ACTION_RATE_LIMIT_WINDOW;
        $max = self::ACTION_RATE_LIMIT_MAX;
        $now = time();
        $bucket = $this->session->get(self::RATE_LIMIT_SESSION_KEY);
        if (!is_array($bucket)) {
            $bucket = [];
        }

        $userId = (int)$this->user->id;
        $key = $action . ':' . $userId;
        $entries = isset($bucket[$key]) && is_array($bucket[$key]) ? $bucket[$key] : [];
        $entries = array_values(array_filter($entries, function ($ts) use ($now, $window) {
            $value = (int)$ts;
            return $value >= $now - $window;
        }));

        if (count($entries) >= $max) {
            $bucket[$key] = $entries;
            $this->session->set(self::RATE_LIMIT_SESSION_KEY, $bucket);
            return false;
        }

        $entries[] = $now;
        $bucket[$key] = $entries;
        $this->session->set(self::RATE_LIMIT_SESSION_KEY, $bucket);
        return true;
    }

    protected function autoValidateProfilePrivateKey(string $algorithm, string $privateKey, string $privateKeyPath, string &$notice): void {
        $algorithm = strtoupper(trim($algorithm));
        if (!in_array($algorithm, ['RS256', 'ES256'], true)) {
            return;
        }

        $validation = $this->validatePrivateKey($algorithm, $privateKey, $privateKeyPath);
        if ($validation['status'] === 'ok') {
            if ($notice !== '') {
                $notice .= ' ';
            }
            $notice .= $this->_('Auto key validation: ') . (string)$validation['message'];
            $this->addLog('jwt.private_key_valid', 'ok', [
                'algorithm' => $algorithm,
                'type' => $validation['type'] ?? '',
                'source' => $validation['source'] ?? '',
                'mode' => 'auto_profile',
            ]);
            return;
        }

        $errorMessage = $this->_('Auto key validation failed: ') . (string)($validation['message'] ?? '');
        if ($notice !== '') {
            $notice .= ' ';
        }
        $notice .= $errorMessage;
        $this->addLog('jwt.private_key_invalid', 'error', [
            'algorithm' => $algorithm,
            'error' => $this->shortenMessage((string)($validation['message'] ?? '')),
            'mode' => 'auto_profile',
        ]);
        $this->error($errorMessage);
    }

    protected function validatePrivateKey(string $algorithm, string $privateKey, string $privateKeyPath): array {
        $algorithm = strtoupper($algorithm);
        if (!extension_loaded('openssl')) {
            return [
                'status' => 'error',
                'message' => $this->_('OpenSSL extension is missing.'),
            ];
        }

        if (!in_array($algorithm, ['RS256', 'ES256'], true)) {
            return [
                'status' => 'ok',
                'message' => $this->_('HS256 does not require a private key.'),
                'source' => $this->_('n/a'),
            ];
        }

        if ($privateKey === '' && $privateKeyPath === '') {
            return [
                'status' => 'error',
                'message' => $this->_('Either private_key or private_key_path is required for key-based algorithms.'),
            ];
        }

        $payload = $privateKey !== '' ? $privateKey : '';
        $source = $payload !== '' ? $this->_('inline') : $this->_('file');
        if ($payload === '') {
            $resolvedKeyPath = $this->resolvePrivateKeyPath($privateKeyPath);
            if ($resolvedKeyPath === '' || !is_readable($resolvedKeyPath)) {
                return [
                    'status' => 'error',
                    'message' => sprintf($this->_('Private key path is not readable: %s'), $privateKeyPath),
                    'source' => $source,
                ];
            }
            $payload = file_get_contents($resolvedKeyPath);
            if ($payload === false || trim($payload) === '') {
                return [
                    'status' => 'error',
                    'message' => $this->_('Unable to read private key file or file is empty.'),
                    'source' => $source,
                ];
            }
        }

        $key = openssl_pkey_get_private($payload);
        if (!$key) {
            return [
                'status' => 'error',
                'message' => $this->_('Unable to parse private key. Check format and key content.'),
                'source' => $source,
                'error' => $this->shortenMessage($this->collectOpenSslErrors()),
            ];
        }

        $details = openssl_pkey_get_details($key);
        if (is_resource($key)) {
            openssl_free_key($key);
        }

        if (!is_array($details)) {
            return [
                'status' => 'error',
                'message' => $this->_('Cannot extract key details from private key.'),
                'source' => $source,
            ];
        }

        $type = $details['type'] ?? '';
        $bits = (int)($details['bits'] ?? 0);
        $curve = isset($details['ec']) && is_array($details['ec']) ? ($details['ec']['curve_name'] ?? '') : '';
        $typeName = $this->keyTypeName((int)$type);

        if ($algorithm === 'RS256' && $typeName !== 'RSA') {
            return [
                'status' => 'error',
                'message' => $this->_('Key is valid, but algorithm RS256 expects RSA key type.'),
                'type' => $typeName,
                'source' => $source,
            ];
        }
        if ($algorithm === 'ES256' && ($typeName !== 'EC' || !in_array(strtolower((string)$curve), ['prime256v1', 'secp256r1'], true))) {
            return [
                'status' => 'error',
                'message' => $this->_('Key is valid, but algorithm ES256 expects an EC P-256 key.'),
                'type' => $typeName,
                'source' => $source,
                'curve' => $curve,
            ];
        }

        return [
            'status' => 'ok',
            'message' => sprintf($this->_('Private key looks valid: %s (%s bits).'), $typeName ?: $type, $bits),
            'type' => $typeName,
            'source' => $source,
            'bits' => $bits,
            'curve' => $curve,
        ];
    }

    protected function collectOpenSslErrors(): string {
        $errors = [];
        while (($error = openssl_error_string()) !== false) {
            $errors[] = $error;
            if (count($errors) >= 5) {
                break;
            }
        }
        if (!$errors) {
            return '';
        }
        return implode('; ', $errors);
    }

    protected function keyTypeName(int $type): string {
        if (!defined('OPENSSL_KEYTYPE_RSA')) {
            return (string)$type;
        }
        if ($type === OPENSSL_KEYTYPE_RSA) {
            return 'RSA';
        }
        if (defined('OPENSSL_KEYTYPE_EC') && $type === OPENSSL_KEYTYPE_EC) {
            return 'EC';
        }
        return (string)$type;
    }

    protected function getStoredProfile(): array {
        $path = $this->getStoredProfilePath();
        if ($path === '' || !is_readable($path)) {
            return [];
        }
        $raw = file_get_contents($path);
        if ($raw === false) {
            return [];
        }
        $decoded = json_decode($raw, true);
        return is_array($decoded) ? $decoded : [];
    }

    protected function saveUserProfile(array $applePreset, array $form): void {
        $path = $this->getStoredProfilePath();
        if ($path === '') {
            return;
        }
        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }
        if (!is_writable($dir)) {
            return;
        }

        $payload = [
            'schema' => 'tokenforge.apple-preset-profile',
            'version' => 1,
            'generated_at' => gmdate('c'),
            'updated_by' => 'user:' . (int)$this->user->id,
            'apple_team_id' => $applePreset['apple_team_id'] ?? '',
            'apple_service_id' => $applePreset['apple_service_id'] ?? '',
            'apple_key_id' => $applePreset['apple_key_id'] ?? '',
            'apple_private_key_path' => $applePreset['apple_private_key_path'] ?? '',
            'algorithm' => (string)($form['algorithm'] ?? ''),
            'key_id' => (string)($form['key_id'] ?? ''),
            'cache_key' => (string)($form['cache_key'] ?? ''),
            'ttl' => (string)($form['ttl'] ?? ''),
            'private_key_path' => (string)($form['private_key_path'] ?? ''),
            'headers_json' => (string)($form['headers_json'] ?? ''),
            'payload_json' => (string)($form['payload_json'] ?? ''),
        ];
        @file_put_contents($path, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), LOCK_EX);
    }

    protected function getStoredProfilePath(): string {
        $config = $this->wire('config');
        $cachePath = is_object($config) && !empty($config->paths->cache) ? $config->paths->cache : sys_get_temp_dir() . '/';
        $safeUserId = (int)$this->user->id;
        return rtrim($cachePath, '/\\\\') . '/tokenforge_user_profile_' . $safeUserId . '.json';
    }

    protected function addLog(string $event, string $status, array $meta = []): void {
        $log = $this->getLog();
        $log[] = [
            'time' => time(),
            'event' => $event,
            'status' => $status,
            'meta' => $meta,
        ];
        if (count($log) > self::AUDIT_LIMIT) {
            $log = array_slice($log, -self::AUDIT_LIMIT);
        }
        $this->session->set('tokenforge_admin_activity_log', $log);
    }

    protected function getLog(): array {
        $log = $this->session->get('tokenforge_admin_activity_log');
        return is_array($log) ? $log : [];
    }

    protected function shortenMessage(string $value): string {
        $value = trim($value);
        if (strlen($value) <= 120) {
            return $value;
        }
        return substr($value, 0, 117) . '...';
    }

    protected function renderActivityLog(array $log, string $formActionUrl): string {
        $formAction = $this->h($formActionUrl);
        $rows = '';
        if (!$log) {
            return '';
        }

        $log = array_reverse($log);
        foreach ($log as $row) {
            if (!is_array($row)) continue;
            $time = is_int($row['time'] ?? null) ? date('Y-m-d H:i:s', $row['time']) : 'n/a';
            $event = $this->h($row['event'] ?? 'event');
            $status = $this->h($row['status'] ?? '');
            $metaParts = [];
            if (is_array($row['meta'] ?? null)) {
                foreach ($row['meta'] as $key => $val) {
                    if ($key === 'error' && is_string($val)) {
                        $metaParts[] = $this->h($this->_($key)) . ': ' . $this->h($this->shortenMessage($val));
                    } elseif (is_scalar($val)) {
                        $metaParts[] = $this->h($key) . ': ' . $this->h($val);
                    }
                }
            }
            $meta = implode(' · ', $metaParts);
            $statusClass = $status === 'ok' ? 'uk-label-success' : 'uk-label-danger';
            $rows .= '<tr>'
                . '<td>' . $this->h($time) . '</td>'
                . '<td><span class="uk-label ' . $statusClass . '">' . $status . '</span></td>'
                . '<td>' . $event . '</td>'
                . '<td style="word-break:break-word;">' . $meta . '</td>'
                . '</tr>';
        }

        $count = count($log);
        $labelClass = $count > 0 ? 'uk-label-success' : 'uk-label-warning';
        return <<<HTML
<div class="tf-panel tf-table-panel">
    <div class="tf-panel-heading"><h2>{$this->_('Activity log (session)')}</h2><p><span class="uk-label {$labelClass}">{$this->_('entries')}: {$count}</span></p></div>
    <form method="post" action="{$formAction}" class="uk-margin-small">
        {$this->session->CSRF->renderInput()}
        <input type="hidden" name="action" value="clear_log">
        <button class="uk-button uk-button-default" type="submit">{$this->_('Clear log')}</button>
    </form>
    <table class="uk-table uk-table-small uk-table-divider">
        <thead>
            <tr>
                <th>{$this->_('Time')}</th>
                <th>{$this->_('Status')}</th>
                <th>{$this->_('Event')}</th>
                <th>{$this->_('Metadata')}</th>
            </tr>
        </thead>
        <tbody>{$rows}</tbody>
    </table>
</div>
HTML;
    }

    protected function renderCopyScript(string $defaultTtl = '3300', string $privateKeyBasePath = '/site/assets/private/', string $cacheKeyPrefix = 'provider_', string $generateTabUrl = ''): string {
        $defaultTtlJson = json_encode((string)max(60, (int)$defaultTtl), JSON_UNESCAPED_SLASHES);
        $privateKeyBasePath = rtrim(trim($privateKeyBasePath), '/\\') . '/';
        $privateKeyBasePathJson = json_encode($privateKeyBasePath, JSON_UNESCAPED_SLASHES);
        $cacheKeyPrefixJson = json_encode(trim($cacheKeyPrefix), JSON_UNESCAPED_SLASHES);
        $generateTabUrlJson = json_encode(htmlspecialchars_decode($generateTabUrl, ENT_QUOTES), JSON_UNESCAPED_SLASHES);
        $demoRsaPrivateKeyJson = json_encode(<<<'PEM'
-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQClCZ6xPuE3C7Lv
1CYaczvq2pbyNCXc317sCydqqL4g9xYFVs3JHnhnZHSjYlz7RHdiZ6IzZjrkYmLK
Pn0pGLOBUDC5byimeHQCjGslcbjdBULUH0emo4WGP3Tm7cyMEmE3vOU0GywwKc8b
FVwvm9R0IwJYvlzAIQT1UsdTY/CwipIBiXIAhE4M2doUcHW1huGnEX21mCY7OKcX
TOln+HAJVF78iVsD5DnSFHLVpuGcpu0Wxpkj9QqcUCGoslXgKZkHGxG7jOxg8KJE
x+6HP6H9HwiAHPdrbr8pf58cIEMCLbZ6Le4u4UEoIyHjPoHcCl9oek+v44NJSG9i
Z+e++SydAgMBAAECgf8d6GJyhVyav4KerA6evzg8JwtthmuYMUAfUji4Q2BBrxnk
hbbd9rmFxowzTChF6keRuFchi03DQZf9mwATgaGgNMLcPb2t46pcITSDYbE+O2ok
XtEafpVwgLdScd5p5vXKeryKdBqUxl8xQxTpZTyKf4CWp7cstxEzFuHcSfc80ls6
Z9gBFF2paxRhmDX+ivJzqGDfZnHKtWryIFY/CXGchQADl1oLmWTMcKRAS6YtCV8/
iD32Un/4efTSYkgNRua8veNhOteGSO/BFs1zFX22pfuHkys/ZuExIS2AUS/MAzql
GyIbkD7MQmSBSuKsr65Bg9/69n9rXHYAcG4wtYECgYEA36ZaTTAvor04ka1QoqlD
qgLpX+AlzrhT7YzPjSwpKgqOooYMKf3d3l3Th/i9T7U15TVnK1B6jGS6f5KhGj6Y
gBPdGIW2Luxtk7c9+vd8pZ713CqWMOatV+wIWW7QMYi+qJJAULq8229yk89NKP4R
mtx0ibyG9IwVwpkj/bIo3F0CgYEAvOjiNIA8jfGPIRonvdHmvb0A2q1XfjxcDCwz
aW1HgVAOR+wPxvNtV777xDCYW1rkDbIyJrbwiotv0xzSsBqN8a5WFUHxwpQAWWzL
BmUaclh3c65jzL+6raCulFhQdIcE8FkhIBZB1nOJ+X+QMoLDoZdulAQKJNpl2+Id
L+KCjUECgYBXLJdcKOEYdNr85WpdzM5EEVh3932lIvIL0OwBoen1qiHItak+IOb/
SuEtycW4sPBuBC/PkVIDMSwEl9nVyfpVSejPKydFCQD5J96v2RGr2NcKV0stimyc
rbLfcTMTa7KtMDyDexYsDjfB53ay+L1R+IYwPdz4qzW8IUcHFw+YPQKBgQCJ7Jpj
bJFJrWkr6PXFIICQXXNHNbIgp58pAAiVW8UOQ835cv/d6RMXMoiNKFHEuWqyGT2G
iKC89qsxfuTQ0MJ8ByYwpRIHV5mdsNHWnHCftbmZC2UwM3fvltZ/1q7/NSlE9j46
OCXflkHRmPJF/rUowPBqPzzMxWwDC2b19DIPQQKBgBKD0a8Bm9+85ws8ziGNFMCE
hAIcowteBY0Po5nGRDmG9ZHK2x7pMH9LejQvQw6M/IaGkeUxHnoTXJZGm9Fwd4Ku
U7beHlWsVmvKCxyEt8NwV5+Wt7gQzgDp+c2CC1zMIzc5ImjjvfAgJ2kMYEjqGu+/
yfVLzrtQto1NcP9WQVf5
-----END PRIVATE KEY-----
PEM, JSON_UNESCAPED_SLASHES);
        $demoEcPrivateKeyJson = json_encode(<<<'PEM'
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgs8gOv2zvtWJRihA9
Jy1KWxNUUFsc2BNrf3Js4xt7t/yhRANCAATw8WwKACOHnej6kjDBcQngQxseJ/gr
JH+EdvW714eQbAVMjYtVoJ5b3Ii8RuxRavuWnYi450bMlP44sYYRn/Lq
-----END PRIVATE KEY-----
PEM, JSON_UNESCAPED_SLASHES);

        return <<<HTML
<script>
;(function () {
    var algorithmSelect = document.querySelector('[data-tf-algorithm]');
    var keyFields = document.querySelectorAll('[data-tf-field="requires-key"]');
    var secretFields = document.querySelectorAll('[data-tf-field="requires-secret"]');
    var generateForm = document.querySelector('[data-tf-generate-form]');
    var presetButtons = document.querySelectorAll('[data-tf-preset-id]');
    var defaultTtl = {$defaultTtlJson};
    var privateKeyBasePath = {$privateKeyBasePathJson};
    var cacheKeyPrefix = {$cacheKeyPrefixJson};
    var generateTabUrl = {$generateTabUrlJson};
    var demoRsaPrivateKey = {$demoRsaPrivateKeyJson};
    var demoEcPrivateKey = {$demoEcPrivateKeyJson};
    var presets = {
        apple_weatherkit: {
            algorithm: 'ES256',
            cache_key: cacheKeyPrefix + 'apple_service_token',
            ttl: defaultTtl,
            key_id: 'APPLE_KEY_ID',
            secret: '',
            private_key_path: '',
            private_key: demoEcPrivateKey,
            headers_json: '{"id":"TEAMID.com.example.weather"}',
            payload_json: '{"iss":"TEAMID","iat":"__IAT__","exp":"__EXP__","sub":"com.example.weather"}',
        },
        android_firebase: {
            algorithm: 'RS256',
            cache_key: 'firebase_service_account_assertion',
            ttl: '3000',
            key_id: 'service-account-private-key-id',
            secret: '',
            private_key_path: '',
            private_key: demoRsaPrivateKey,
            headers_json: '{"kid":"service-account-private-key-id"}',
            payload_json: '{"iss":"service-account@example-project.iam.gserviceaccount.com","scope":"https://www.googleapis.com/auth/firebase.messaging","aud":"https://oauth2.googleapis.com/token","iat":"__IAT__","exp":"__EXP__"}',
        },
        samsung_services: {
            algorithm: 'RS256',
            cache_key: 'samsung_service_assertion',
            ttl: '1800',
            key_id: 'samsung-key-id',
            secret: '',
            private_key_path: '',
            private_key: demoRsaPrivateKey,
            headers_json: '{"kid":"samsung-key-id"}',
            payload_json: '{"iss":"your-samsung-client-id","aud":"https://api.example.samsung.com","iat":"__IAT__","exp":"__EXP__"}',
        },
        hs256: {
            algorithm: 'HS256',
            cache_key: 'session_hs256_token',
            ttl: defaultTtl,
            key_id: 'demo-key-id',
            secret: 'replace-me',
            private_key_path: '',
            private_key: '',
            headers_json: '{"alg":"HS256"}',
            payload_json: '{"iss":"demo-service","aud":"api.example.com","iat":"__IAT__","exp":"__EXP__"}',
        },
        es256: {
            algorithm: 'ES256',
            cache_key: 'generic_es256_assertion',
            ttl: defaultTtl,
            key_id: 'ec-key-id',
            secret: '',
            private_key_path: '',
            private_key: demoEcPrivateKey,
            headers_json: '{"kid":"ec-key-id"}',
            payload_json: '{"iss":"example-service","aud":"api.example.com","iat":"__IAT__","exp":"__EXP__"}',
        },
        rs256: {
            algorithm: 'RS256',
            cache_key: 'service_rs256_token',
            ttl: '1800',
            key_id: 'rs-key-id',
            secret: '',
            private_key_path: '',
            private_key: demoRsaPrivateKey,
            headers_json: '{"kid":"rs-key-id"}',
            payload_json: '{"iss":"example-service","iat":"__IAT__","exp":"__EXP__"}',
        }
    };

    function updateAlgorithmFields() {
        if (!algorithmSelect) {
            return;
        }
        var isAsymmetric = algorithmSelect.value !== 'HS256';
        for (var i = 0; i < keyFields.length; i++) {
            keyFields[i].classList.toggle('uk-hidden', !isAsymmetric);
        }
        for (var j = 0; j < secretFields.length; j++) {
            secretFields[j].classList.toggle('uk-hidden', isAsymmetric);
        }
    }

    function fillJsonField(field, value) {
        if (!field) return;
        if (!value) {
            field.value = '';
            return;
        }
        try {
            field.value = JSON.stringify(JSON.parse(value), null, 2);
        } catch (e) {
            field.value = value;
        }
    }

    function applyPresetValues(presetId) {
        if (!generateForm || !presets[presetId]) {
            return;
        }
        var preset = presets[presetId];
        var now = Math.floor(Date.now() / 1000);
        var payloadTemplate = String(preset.payload_json || '{}')
            .replace('__IAT__', String(now))
            .replace('__EXP__', String(now + 3600));

        if (algorithmSelect) {
            algorithmSelect.value = preset.algorithm;
        }
        fillFormField('[name="cache_key"]', preset.cache_key || '');
        fillFormField('[name="ttl"]', String(preset.ttl || ''));
        fillFormField('[name="key_id"]', preset.key_id || '');
        fillFormField('[name="secret"]', preset.secret || '');
        fillFormField('[name="private_key_path"]', preset.private_key_path || '');
        fillFormField('[name="private_key"]', preset.private_key || '');
        fillJsonField(generateForm.querySelector('[name="headers_json"]'), preset.headers_json);
        fillJsonField(generateForm.querySelector('[name="payload_json"]'), payloadTemplate);
        updateAlgorithmFields();
        activateGeneratorTab();
    }

    function fillFormField(selector, value) {
        var el = generateForm ? generateForm.querySelector(selector) : document.querySelector(selector);
        if (!el) {
            return;
        }
        el.value = value;
    }

    function activateGeneratorTab() {
        if (!generateForm) {
            return;
        }
        var generatorPanel = generateForm.closest('li');
        var switcher = generatorPanel ? generatorPanel.parentNode : null;
        if (switcher) {
            var panels = switcher.children;
            for (var i = 0; i < panels.length; i++) {
                panels[i].classList.remove('uk-active');
            }
            generatorPanel.classList.add('uk-active');
        }

        var navLinks = document.querySelectorAll('.tf-admin-nav .uk-subnav a');
        for (var j = 0; j < navLinks.length; j++) {
            var item = navLinks[j].closest('li');
            if (!item) {
                continue;
            }
            var href = navLinks[j].getAttribute('href') || '';
            item.classList.toggle('uk-active', href.indexOf('tab=generate-jwt') !== -1 || navLinks[j].href === generateTabUrl);
        }

        if (generateTabUrl && window.history && window.history.pushState) {
            window.history.pushState({}, '', currentTabUrl('generate-jwt'));
        }
        generateForm.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function currentTabUrl(tabName) {
        try {
            var url = new URL(window.location.href);
            url.searchParams.set('tab', tabName);
            return url.pathname + url.search + url.hash;
        } catch (e) {
            return generateTabUrl || window.location.href;
        }
    }

    function showCopyFeedback(target) {
        var container = target.parentNode;
        if (!container) return;
        var feedback = container.querySelector('.tf-copy-feedback');
        if (!feedback) return;
        feedback.classList.add('is-visible');
        if (window._tfCopyFeedbackTimer) {
            clearTimeout(window._tfCopyFeedbackTimer);
        }
        window._tfCopyFeedbackTimer = setTimeout(function () {
            feedback.classList.remove('is-visible');
        }, 1300);
    }

    function copyText(selector) {
        var el = document.querySelector(selector);
        if (!el) return;
        var text = el.value || el.textContent || '';
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).catch(function () {
                fallback(text);
            });
        } else {
            fallback(text);
        }
    }

    function fallback(text) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    }

    document.addEventListener('click', function (evt) {
        var target = evt.target;
        if (!target || target.tagName !== 'BUTTON' || !target.getAttribute('data-copy-target')) return;
        evt.preventDefault();
        copyText(target.getAttribute('data-copy-target'));
        showCopyFeedback(target);
    });

    if (algorithmSelect) {
        algorithmSelect.addEventListener('change', updateAlgorithmFields);
        updateAlgorithmFields();
    }

    if (presetButtons.length) {
        for (var i = 0; i < presetButtons.length; i++) {
            presetButtons[i].addEventListener('click', function () {
                applyPresetValues(this.getAttribute('data-tf-preset-id'));
            });
        }
    }
})();
</script>
HTML;
    }

    protected function selected(string $current, string $expected): string {
        return $current === $expected ? ' selected' : '';
    }
}
