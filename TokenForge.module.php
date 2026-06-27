<?php namespace ProcessWire;

require_once __DIR__ . '/src/JwtBuilder.php';
require_once __DIR__ . '/src/KeyLoader.php';

/**
 * TokenForge
 *
 * @author  Maxim Semenov (smnv.org)
 * @version 100
 * @license MIT
 */
class TokenForge extends WireData implements Module, ConfigurableModule {

    protected const MODULE_NAME = 'TokenForge';

    protected ?JwtBuilder $jwtBuilder = null;

    public static function getModuleInfo(): array {
        return [
            'title'    => self::MODULE_NAME,
            'version'  => 100,
            'summary'  => 'TokenForge creates signed JWT tokens for ProcessWire modules and integrations. Supports HS256, RS256 and ES256 with ProcessWire cache integration.',
            'author'   => 'Maxim Semenov',
            'href'     => 'https://smnv.org',
            'autoload' => false,
            'singular' => true,
            'requires' => ['PHP>=8.1.0'],
            'installs' => ['ProcessTokenForge'],
        ];
    }

    public function __construct() {
        parent::__construct();
    }

    public function createJwt(array $options): string {
        return $this->getJwtBuilder()->create($options);
    }

    public function adminDefaults(): array {
        return [
            'default_ttl' => max(60, (int)($this->default_ttl ?: 3300)),
            'private_key_base_path' => trim((string)($this->private_key_base_path ?: '/site/assets/private/')),
            'cache_key_prefix' => trim((string)($this->cache_key_prefix ?: 'provider_')),
            'show_official_docs' => (int)($this->show_official_docs ?? 1) ? 1 : 0,
        ];
    }

    public static function getModuleConfigInputfields(array $data): InputfieldWrapper {
        $data = array_merge([
            'default_ttl' => 3300,
            'private_key_base_path' => '/site/assets/private/',
            'cache_key_prefix' => 'provider_',
            'show_official_docs' => 1,
        ], $data);

        $modules = wire('modules');
        $inputfields = new InputfieldWrapper();

        $f = $modules->get('InputfieldInteger');
        $f->attr('name', 'default_ttl');
        $f->label = __('Default cached token TTL');
        $f->description = __('Used as the initial TTL value in the admin generator and presets. TokenForge still clamps cached JWT lifetime to payload exp when exp is present.');
        $f->notes = __('Safe default: 3300 seconds for one-hour provider tokens.');
        $f->attr('value', (int)$data['default_ttl']);
        $f->attr('min', 60);
        $inputfields->add($f);

        $f = $modules->get('InputfieldText');
        $f->attr('name', 'private_key_base_path');
        $f->label = __('Private key path hint');
        $f->description = __('Shown in admin placeholders only. Private keys are not stored in module settings.');
        $f->notes = __('Recommended: /site/assets/private/');
        $f->attr('value', (string)$data['private_key_base_path']);
        $inputfields->add($f);

        $f = $modules->get('InputfieldText');
        $f->attr('name', 'cache_key_prefix');
        $f->label = __('Cache key prefix hint');
        $f->description = __('Used by admin examples to keep cache keys readable. It does not change runtime API calls.');
        $f->attr('value', (string)$data['cache_key_prefix']);
        $inputfields->add($f);

        $f = $modules->get('InputfieldCheckbox');
        $f->attr('name', 'show_official_docs');
        $f->label = __('Show official documentation links');
        $f->description = __('Displays provider documentation links in the admin helper panels.');
        $f->attr('value', 1);
        if (!empty($data['show_official_docs'])) {
            $f->attr('checked', 'checked');
        }
        $inputfields->add($f);

        return $inputfields;
    }

    public function createCachedJwt(string $cacheKey, array $options): string {
        $cacheKey = trim($cacheKey);
        if ($cacheKey === '') {
            throw new WireException('TokenForge: Missing cache key.');
        }

        if (!isset($options['payload']) || !is_array($options['payload'])) {
            throw new WireException('TokenForge: payload must be an array.');
        }

        $cacheId = $this->cacheId($cacheKey, $options);
        $cache = $this->wire('cache');
        if (!is_object($cache) || !method_exists($cache, 'get')) {
            throw new \RuntimeException('TokenForge: ProcessWire cache is unavailable.');
        }

        $cached = $cache->get($cacheId);
        if (is_string($cached) && $cached !== '') {
            return $cached;
        }

        $jwt = $this->createJwt($options);
        $ttl = $this->calculateCacheTtl($options, $options['payload']);

        if ($ttl <= 0) {
            throw new WireException('TokenForge: Cache TTL is not valid for this token.');
        }

        $cache->save($cacheId, $jwt, $ttl);
        $this->rememberCacheId($cacheKey, $cacheId, $ttl);
        return $jwt;
    }

    public function clearCachedJwt(string $cacheKey): void {
        $cacheKey = trim($cacheKey);
        if ($cacheKey === '') {
            return;
        }

        $cache = $this->wire('cache');
        if (is_object($cache) && method_exists($cache, 'delete')) {
            $cache->delete($this->legacyCacheId($cacheKey));

            $indexId = $this->cacheIndexId($cacheKey);
            $ids = method_exists($cache, 'get') ? $cache->get($indexId) : [];
            if (is_array($ids)) {
                foreach ($ids as $id) {
                    if (is_string($id) && str_starts_with($id, 'TokenForge.jwt.')) {
                        $cache->delete($id);
                    }
                }
            }
            $cache->delete($indexId);
        }
    }

    protected function getJwtBuilder(): JwtBuilder {
        if ($this->jwtBuilder === null) {
            $config = $this->wire('config');
            $root = $this->processWireRootPath();
            $this->jwtBuilder = new JwtBuilder(new KeyLoader($root));
        }
        return $this->jwtBuilder;
    }

    protected function processWireRootPath(): string {
        $config = $this->wire('config');
        if (is_object($config) && !empty($config->paths->root)) {
            return (string)$config->paths->root;
        }
        if (is_object($config) && !empty($config->paths->site)) {
            return dirname(rtrim((string)$config->paths->site, '/\\')) . '/';
        }
        return dirname(__DIR__, 3) . '/';
    }

    protected function legacyCacheId(string $cacheKey): string {
        return 'TokenForge.jwt.' . sha1($cacheKey);
    }

    protected function cacheId(string $cacheKey, array $options): string {
        return 'TokenForge.jwt.' . hash('sha256', $cacheKey . '|' . $this->cacheFingerprint($options));
    }

    protected function cacheIndexId(string $cacheKey): string {
        return 'TokenForge.jwt.index.' . sha1($cacheKey);
    }

    protected function rememberCacheId(string $cacheKey, string $cacheId, int $ttl): void {
        $cache = $this->wire('cache');
        if (!is_object($cache) || !method_exists($cache, 'get') || !method_exists($cache, 'save')) {
            return;
        }

        $indexId = $this->cacheIndexId($cacheKey);
        $ids = $cache->get($indexId);
        $ids = is_array($ids) ? array_values(array_filter($ids, 'is_string')) : [];
        if (!in_array($cacheId, $ids, true)) {
            $ids[] = $cacheId;
        }

        $cache->save($indexId, array_slice($ids, -50), max($ttl, 3600));
    }

    protected function cacheFingerprint(array $options): string {
        $normalized = $this->normalizeCacheOptions($options);
        return hash('sha256', json_encode($normalized, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '');
    }

    protected function normalizeCacheOptions(array $options): array {
        $normalized = $options;
        foreach (['secret', 'private_key', 'private_key_password', 'passphrase'] as $key) {
            if (isset($normalized[$key]) && (string)$normalized[$key] !== '') {
                $normalized[$key] = 'sha256:' . hash('sha256', (string)$normalized[$key]);
            }
        }
        if (isset($normalized['payload']) && is_array($normalized['payload'])) {
            unset($normalized['payload']['iat'], $normalized['payload']['exp'], $normalized['payload']['nbf']);
        }
        $this->ksortRecursive($normalized);
        return $normalized;
    }

    protected function ksortRecursive(array &$value): void {
        ksort($value);
        foreach ($value as &$item) {
            if (is_array($item)) {
                $this->ksortRecursive($item);
            }
        }
        unset($item);
    }

    protected function calculateCacheTtl(array $options, array $payload): int {
        $ttl = isset($options['ttl']) ? (int)$options['ttl'] : 0;

        if (!array_key_exists('exp', $payload)) {
            if ($ttl <= 0) {
                throw new WireException('TokenForge: Missing TTL for cached token.');
            }
            return $ttl;
        }

        $exp = (int)$payload['exp'];
        $safeTtl = $exp - time() - 60;
        if ($safeTtl <= 0) {
            throw new WireException('TokenForge: Payload exp is already expired.');
        }

        if ($ttl <= 0 || $ttl > $safeTtl) {
            return $safeTtl;
        }
        return $ttl;
    }
}
