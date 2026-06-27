<?php namespace ProcessWire;

/**
 * ES256 signer implementation.
 * NOTE: Uses OpenSSL only. No external dependency is required.
 * If OpenSSL cannot produce valid ECDSA signature conversion for your environment,
 * fallback to firebase/php-jwt should be considered for full compatibility.
 */
final class Es256Signer implements SignerInterface {

    public function getAlgorithm(): string {
        return 'ES256';
    }

    public function sign(string $data, array $options): string {
        if (!function_exists('openssl_sign')) {
            throw new \RuntimeException('TokenForge: OpenSSL extension is required for ES256 signing.');
        }

        $privateKey = isset($options['private_key']) ? (string)$options['private_key'] : '';
        if ($privateKey === '') {
            throw new WireException('TokenForge: ES256 requires private_key or private_key_path.');
        }

        $passphrase = isset($options['private_key_password']) ? (string)$options['private_key_password'] : '';
        $resource = @openssl_pkey_get_private($privateKey, $passphrase);
        if ($resource === false) {
            throw new WireException('TokenForge: Invalid private key for ES256.');
        }

        $details = @openssl_pkey_get_details($resource);
        if (!is_array($details) || !$this->isP256Key($details)) {
            throw new WireException('TokenForge: ES256 requires an EC P-256 private key.');
        }

        if (!@openssl_sign($data, $signatureDer, $resource, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('TokenForge: Failed to sign JWT.');
        }

        $rawSignature = $this->derToJose($signatureDer);
        if ($rawSignature === '') {
            throw new \RuntimeException('TokenForge: Failed to normalize ES256 signature.');
        }

        return Base64Url::encode($rawSignature);
    }

    protected function isP256Key(array $details): bool {
        $type = (int)($details['type'] ?? -1);
        if (!defined('OPENSSL_KEYTYPE_EC') || $type !== OPENSSL_KEYTYPE_EC) {
            return false;
        }

        $curve = '';
        if (isset($details['ec']) && is_array($details['ec'])) {
            $curve = strtolower((string)($details['ec']['curve_name'] ?? ''));
        }

        return in_array($curve, ['prime256v1', 'secp256r1'], true);
    }

    protected function derToJose(string $der): string {
        $len = strlen($der);
        if ($len < 8) {
            return '';
        }

        $offset = 0;
        if (!self::consumeByte($der, $offset, 0x30)) return '';

        $seqLength = self::readAsn1Length($der, $offset);
        if ($seqLength <= 0 || ($offset + $seqLength) > $len) return '';

        if (!self::consumeByte($der, $offset, 0x02)) return '';
        $rLength = self::readAsn1Length($der, $offset);
        if ($rLength <= 0) return '';

        if (($offset + $rLength) > $len) return '';
        $r = substr($der, $offset, $rLength);
        $offset += $rLength;

        if (!self::consumeByte($der, $offset, 0x02)) return '';
        $sLength = self::readAsn1Length($der, $offset);
        if ($sLength <= 0) return '';

        if (($offset + $sLength) > $len) return '';
        $s = substr($der, $offset, $sLength);

        $r = ltrim($r, "\0");
        $s = ltrim($s, "\0");
        $r = str_pad(substr($r, -32), 32, "\0", STR_PAD_LEFT);
        $s = str_pad(substr($s, -32), 32, "\0", STR_PAD_LEFT);

        return $r . $s;
    }

    protected static function consumeByte(string $data, int &$offset, int $expected): bool {
        if ($offset >= strlen($data)) return false;
        if (ord($data[$offset]) !== $expected) return false;
        $offset++;
        return true;
    }

    protected static function readAsn1Length(string $data, int &$offset): int {
        if ($offset >= strlen($data)) return 0;

        $byte = ord($data[$offset++]);
        if (($byte & 0x80) === 0) return $byte;

        $num = $byte & 0x7f;
        if ($num === 0 || $num > 4) return 0;
        if (($offset + $num) > strlen($data)) return 0;

        $length = 0;
        for ($i = 0; $i < $num; $i++) {
            $length = ($length << 8) | ord($data[$offset++]);
        }
        return $length;
    }
}
