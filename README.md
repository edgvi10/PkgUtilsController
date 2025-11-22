# PkgUtils

Uma biblioteca PHP com métodos utilitários para facilitar o desenvolvimento de aplicações.

## Instalação

```bash
composer require edgvi10/utils
```

## Recursos

### Gerenciamento de Ambiente

- **`env($path)`** - Carrega variáveis de ambiente de um arquivo .env
- **`getEnvironmentInfo()`** - Retorna informações sobre o ambiente PHP
- **`setupEnvironment($options)`** - Configura o ambiente PHP (timezone, error reporting, etc.)

### UUID

- **`generateUUIDv4()`** - Gera um UUID versão 4
- **`isValidUUIDv4($uuid)`** - Valida um UUID v4

### Sanitização e Validação

- **`sanitizeString($string)`** - Sanitiza uma string removendo caracteres especiais
- **`sanitizeEmail($email)`** - Sanitiza um endereço de e-mail
- **`escapeNumbers($number)`** - Remove tudo exceto números

### Senhas

- **`hashPassword($password)`** - Cria hash de senha usando bcrypt
- **`verifyPassword($password, $hash)`** - Verifica uma senha contra seu hash

### Strings e Geração

- **`generateRandomString($length)`** - Gera string aleatória

### Data e Hora

- **`getCurrentTimestamp($timezone)`** - Obtém timestamp atual
- **`formatDate($timestamp, $format, $timezone)`** - Formata timestamp

### JSON

- **`isJsonString($string)`** - Verifica se uma string é JSON válido
- **`toJson($data)`** - Converte dados para JSON formatado
- **`fromJson($jsonString, $assoc)`** - Decodifica JSON

### Arrays

- **`arrayFlatten($array, $prefix)`** - Achata array multidimensional

### Base64

- **`isBase64($string)`** - Verifica se string é Base64 válido
- **`base64ToFile($base64String, $outputFile)`** - Converte Base64 para arquivo
- **`fileToBase64($filePath)`** - Converte arquivo para Base64
- **`base64Encode($data)`** - Codifica em Base64 URL-safe
- **`base64Decode($data)`** - Decodifica Base64 URL-safe

### Criptografia AES

- **`AESEncrypt($plaintext, $key)`** - Criptografa dados usando AES-256-CBC
- **`AESDecrypt($ciphertextBase64, $key)`** - Descriptografa dados AES-256-CBC

## Uso

```php
<?php

use EDGVI10\Controllers\UtilitiesController;

// Gerar UUID
$uuid = UtilitiesController::generateUUIDv4();

// Validar UUID
if (UtilitiesController::isValidUUIDv4($uuid)) {
    echo "UUID válido: $uuid";
}

// Sanitizar string
$texto = UtilitiesController::sanitizeString("Olá <script>alert('xss')</script>");

// Hash de senha
$hash = UtilitiesController::hashPassword("minhaSenha123");

// Verificar senha
if (UtilitiesController::verifyPassword("minhaSenha123", $hash)) {
    echo "Senha correta!";
}

// Trabalhar com JSON
$data = ["nome" => "João", "idade" => 30];
$json = UtilitiesController::toJson($data);
$decoded = UtilitiesController::fromJson($json);

// Criptografia AES
$chave = "minha-chave-secreta-32-caracteres";
$encrypted = UtilitiesController::AESEncrypt("dados sensíveis", $chave);
$decrypted = UtilitiesController::AESDecrypt($encrypted, $chave);

// Configurar ambiente
UtilitiesController::setupEnvironment([
    'environment' => 'production',
    'timezone' => 'America/Sao_Paulo',
    'errorLog' => '/var/log/php_errors.log'
]);

// Obter informações do ambiente
$info = UtilitiesController::getEnvironmentInfo();
```

## Requisitos

- PHP >= 7.4
- Extensões: openssl, json

## Licença

MIT

## Autor

EDGVI10
