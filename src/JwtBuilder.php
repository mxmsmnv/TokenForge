<?php namespace ProcessWire;

require_once __DIR__ . '/SignerInterface.php';
require_once __DIR__ . '/Signer/Hs256Signer.php';
require_once __DIR__ . '/Signer/Rs256Signer.php';
require_once __DIR__ . '/Signer/Es256Signer.php';
require_once __DIR__ . '/Base64Url.php';
require_once __DIR__ . '/KeyLoader.php';

final class JwtBuilder {

    public function __construct(protected readonly KeyLoader $keyLoader) {
    }

    public function create(array $options): string {
        $algorithm = strtoupper(trim((string)($options['algorithm'] ?? '')));
        if ($algorithm === '') {
            throw new WireException('TokenForge: Missing algorithm.');
        }

        if (!in_array($algorithm, ['HS256', 'RS256', 'ES256'], true)) {
            throw new WireException('TokenForge: Unsupported algorithm.');
        }

        $payload = $options['payload'] ?? null;
        if (!is_array($payload) || $payload === []) {
            throw new WireException('TokenForge: payload must be a non-empty array.');
        }

        if (array_key_exists('exp', $payload) && (int)$payload['exp'] <= time()) {
            throw new WireException('TokenForge: Payload exp is already expired.');
        }

        $header = $this->buildHeader($algorithm, $options['key_id'] ?? null, $options['headers'] ?? []);
        $claims = $this->encode($payload);
        $base = $this->encode($header) . '.' . $claims;

        $signingData = match ($algorithm) {
            'HS256' => $this->getHs256Signer()->sign($base, $this->resolveSharedSecret($options)),
            'RS256' => $this->getRs256Signer()->sign($base, $this->resolveRsaKey($options)),
            'ES256' => $this->getEs256Signer()->sign($base, $this->resolveEcKey($options)),
        };

        return $base . '.' . $signingData;
    }

    protected function buildHeader(string $algorithm, mixed $keyId = null, mixed $customHeaders = []): array {
        if (!is_array($customHeaders)) {
            $customHeaders = [];
        }

        $header = [
            'typ' => 'JWT',
            'alg' => $algorithm,
        ];

        if (is_string($keyId) && $keyId !== '') {
            $header['kid'] = $keyId;
        }

        foreach ($customHeaders as $key => $value) {
            if (!is_string($key) || in_array($key, ['alg', 'typ'], true)) {
                continue;
            }
            $header[$key] = $value;
        }

        return $header;
    }

    protected function resolveSharedSecret(array $options): array {
        $secret = isset($options['secret']) ? (string)$options['secret'] : '';
        if ($secret === '') {
            throw new WireException('TokenForge: HS256 requires secret.');
        }
        return ['secret' => $secret];
    }

    protected function resolveRsaKey(array $options): array {
        $private = isset($options['private_key']) ? (string)$options['private_key'] : '';
        if ($private === '') {
            $path = isset($options['private_key_path']) ? (string)$options['private_key_path'] : '';
            if ($path === '') {
                throw new WireException('TokenForge: RS256 requires private_key or private_key_path.');
            }
            $private = $this->keyLoader->loadPrivateKey($path);
        }

        $out = ['private_key' => $private];
        if (!empty($options['private_key_password'])) {
            $out['private_key_password'] = (string)$options['private_key_password'];
        }
        if (!empty($options['passphrase'])) {
            $out['private_key_password'] = (string)$options['passphrase'];
        }
        return $out;
    }

    protected function resolveEcKey(array $options): array {
        $private = isset($options['private_key']) ? (string)$options['private_key'] : '';
        if ($private === '') {
            $path = isset($options['private_key_path']) ? (string)$options['private_key_path'] : '';
            if ($path === '') {
                throw new WireException('TokenForge: ES256 requires private_key or private_key_path.');
            }
            $private = $this->keyLoader->loadPrivateKey($path);
        }

        $out = ['private_key' => $private];
        if (!empty($options['private_key_password'])) {
            $out['private_key_password'] = (string)$options['private_key_password'];
        }
        if (!empty($options['passphrase'])) {
            $out['private_key_password'] = (string)$options['passphrase'];
        }
        return $out;
    }

    protected function encode(array $data): string {
        $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new \RuntimeException('TokenForge: Failed to encode JWT payload.');
        }
        return Base64Url::encode($json);
    }

    protected function getHs256Signer(): SignerInterface {
        return new Hs256Signer();
    }

    protected function getRs256Signer(): SignerInterface {
        return new Rs256Signer();
    }

    protected function getEs256Signer(): SignerInterface {
        return new Es256Signer();
    }
}
