<?php

namespace EDGVI10\Controllers;

class UtilsController
{
    public function __construct()
    {
        return $this;
    }

    public function env($path = null)
    {
        if ($path !== null && file_exists($path)) {
            $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                if (strpos(trim($line), "#") === 0) continue;
                list($name, $value) = explode("=", $line, 2);
                $name = trim($name);
                $value = trim($value);
                if (!array_key_exists($name, $_ENV) && !getenv($name)) {
                    putenv(sprintf("%s=%s", $name, $value));
                    $_ENV[$name] = $value;
                }
            }
        }
    }

    public static function getEnvironmentInfo()
    {
        return [
            "environment" => defined("ENVIRONMENT") ? ENVIRONMENT : "development",
            "phpVersion" => phpversion(),
            "memoryLimit" => ini_get("memory_limit"),
            "maxExecutionTime" => ini_get("max_execution_time"),
            "serverOS" => PHP_OS . " " . PHP_OS_FAMILY . " " . (PHP_INT_SIZE * 8) . " bit",
            "sapiName" => php_sapi_name(),
            "loadedExtensions" => get_loaded_extensions(),
            "iniSettings" => ini_get_all(),
        ];
    }

    public static function setupEnvironment($options = [])
    {
        define("ENVIRONMENT", $options["environment"] ?? "development");

        $timezone = $options["timezone"] ?? "UTC";
        $errorReportingLevel = $options["errorReportingLevel"] ?? (E_ERROR | E_WARNING | E_PARSE);

        date_default_timezone_set($timezone);
        error_reporting($errorReportingLevel);
        ini_set("display_errors", "1");
        ini_set("log_errors", "1");

        if (ENVIRONMENT === "production") {
            ini_set("display_errors", "0");
            ini_set("log_errors", "1");
            ini_set("error_log", $options["errorLog"] ?? "/var/log/php_errors.log");
            ini_set("error_reporting", E_ALL & ~E_NOTICE & ~E_DEPRECATED);
        }
    }

    public static function generateUUIDv4()
    {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40); // versão 4
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80); // variante RFC 4122

        return vsprintf("%s%s-%s-%s-%s-%s%s%s", str_split(bin2hex($data), 4));
    }

    public static function isValidUUIDv4($uuid)
    {
        return preg_match("/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i", $uuid) === 1;
    }

    public static function sanitizeString($string)
    {
        $string = trim($string);
        $string = stripslashes($string);
        $string = htmlspecialchars($string, ENT_QUOTES, "UTF-8");
        // preg_replace to replace special characters to normal characters like é to e and ç to c
        $string = preg_replace("/[^\p{L}\p{N}\s]/u", "", $string);
        $string = preg_replace("/\s+/", " ", $string);
        return $string;
    }

    public static function sanitizeEmail($email)
    {
        return filter_var(trim($email), FILTER_SANITIZE_EMAIL);
    }

    public static function escapeNumbers($number)
    {
        return preg_replace("/[^\d]/", "", $number);
    }

    public static function hashPassword($password)
    {
        return password_hash($password, PASSWORD_BCRYPT);
    }

    public static function verifyPassword($password, $hash)
    {
        return password_verify($password, $hash);
    }

    public static function generateRandomString($length = 16)
    {
        $characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $charactersLength = strlen($characters);
        $randomString = "";
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[random_int(0, $charactersLength - 1)];
        }
        return $randomString;
    }

    public static function getCurrentTimestamp($timezone = "UTC")
    {
        $date = new \DateTime("now", new \DateTimeZone($timezone));
        return $date->getTimestamp();
    }

    public static function formatDate($timestamp, $format = "Y-m-d H:i:s", $timezone = "UTC")
    {
        $date = new \DateTime("@" . $timestamp);
        $date->setTimezone(new \DateTimeZone($timezone));
        return $date->format($format);
    }

    public static function isJsonString($string)
    {
        json_decode($string);
        return (json_last_error() == JSON_ERROR_NONE);
    }

    public static function toJson($data)
    {
        return json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
    }

    public static function fromJson($jsonString, $assoc = true)
    {
        if (!self::isJsonString($jsonString)) throw new \InvalidArgumentException("Invalid JSON string provided.");
        return json_decode($jsonString, $assoc, 512, JSON_THROW_ON_ERROR);
    }

    public static function arrayFlatten($array, $prefix = "")
    {
        $result = [];
        foreach ($array as $key => $value) {
            $newKey = $prefix === "" ? $key : $prefix . "_" . $key;
            if (is_array($value)) {
                $result = array_merge($result, self::arrayFlatten($value, $newKey));
            } else {
                $result[$newKey] = $value;
            }
        }
        return $result;
    }

    public static function isBase64($string)
    {
        $decoded = base64_decode($string, true);
        if ($decoded === false) {
            return false;
        }
        return base64_encode($decoded) === $string;
    }

    public static function base64ToFile($base64String, $outputFile)
    {
        if (!self::isBase64($base64String)) throw new \InvalidArgumentException("Invalid Base64 string provided.");
        $data = base64_decode($base64String);
        file_put_contents($outputFile, $data);
        return $outputFile;
    }

    public static function fileToBase64($filePath)
    {
        if (!file_exists($filePath)) throw new \InvalidArgumentException("File does not exist: $filePath");
        $data = file_get_contents($filePath);
        return base64_encode($data);
    }

    public function base64Encode($data)
    {
        return rtrim(strtr(base64_encode($data), "+/", "-_"), "=");
    }

    public function base64Decode($data)
    {
        $padding = 4 - (strlen($data) % 4);
        if ($padding < 4) {
            $data .= str_repeat("=", $padding);
        }
        return base64_decode(strtr($data, "-_", "+/"));
    }

    public static function AESEncrypt($plaintext, $key)
    {
        if (is_object($plaintext) || is_array($plaintext)) $plaintext = self::toJson($plaintext);

        $ivLength = openssl_cipher_iv_length("AES-256-CBC");
        $iv = openssl_random_pseudo_bytes($ivLength);
        $ciphertext = openssl_encrypt($plaintext, "AES-256-CBC", $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $ciphertext);
    }

    public static function AESDecrypt($ciphertextBase64, $key)
    {
        $result = null;
        $ciphertextDec = base64_decode($ciphertextBase64);
        $ivLength = openssl_cipher_iv_length("AES-256-CBC");
        $iv = substr($ciphertextDec, 0, $ivLength);
        $ciphertext = substr($ciphertextDec, $ivLength);
        $result = openssl_decrypt($ciphertext, "AES-256-CBC", $key, OPENSSL_RAW_DATA, $iv);

        if ($result === false) throw new \RuntimeException("Decryption failed.");

        return $result;
    }
}
