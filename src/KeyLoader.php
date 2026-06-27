<?php namespace ProcessWire;

final class KeyLoader {

    public function __construct(protected readonly string $processWireRoot = '') {
    }

    public function loadPrivateKey(string $path): string {
        $path = trim($path);
        if ($path === '') {
            throw new WireException('TokenForge: Missing private key path.');
        }

        $fullPath = $this->resolvePrivateKeyPath($path);

        if (!is_file($fullPath)) {
            throw new WireException('TokenForge: Private key file not found.');
        }

        if (!is_readable($fullPath)) {
            throw new WireException('TokenForge: Private key file is not readable.');
        }

        $contents = file_get_contents($fullPath);
        if ($contents === false) {
            throw new \RuntimeException('TokenForge: Failed to read private key file.');
        }

        return trim($contents);
    }

    public function resolvePrivateKeyPath(string $path): string {
        if ($this->isAbsolutePath($path) && !str_starts_with($path, '/site/')) {
            return $path;
        }

        if (str_starts_with($path, '/site/')) {
            $path = substr($path, 1);
        }

        if (!$this->processWireRoot) {
            throw new \RuntimeException('TokenForge: Cannot resolve relative private key path.');
        }

        return rtrim(str_replace('/', DIRECTORY_SEPARATOR, $this->processWireRoot), DIRECTORY_SEPARATOR)
             . DIRECTORY_SEPARATOR
             . ltrim(str_replace('/', DIRECTORY_SEPARATOR, $path), DIRECTORY_SEPARATOR);
    }

    protected function isAbsolutePath(string $path): bool {
        return str_starts_with($path, '/') || preg_match('/^[A-Za-z]:[\\\\\/]/', $path) === 1;
    }
}
