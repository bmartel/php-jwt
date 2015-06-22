<?php namespace Bmartel\JWT;

use Bmartel\JWT\Exceptions\SignatureInvalidException;
use Bmartel\JWT\Exceptions\BeforeValidException;
use Bmartel\JWT\Exceptions\ExpiredException;
use UnexpectedValueException;
use DomainException;
use ArrayAccess;
use DateTime;

/**
 * JSON Web Token implementation, based on this spec:
 * http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06
 *
 * PHP version 5
 *
 * @author   Neuman Vong <neuman@twilio.com>
 * @author   Anant Narayanan <anant@php.net>
 * @author   Brandon Martel <brandonmartel@gmail.com>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/bmartel/php-jwt
 */
class JWTService
{

    /**
     * When checking nbf, iat or expiration times,
     * we want to provide some extra buffer time to
     * account for clock skew.
     */
    protected $bufferTime;

    /**
     * The current hashing algorithm being used
     * to encode and decode tokens.
     *
     * @var array
     */
    protected $currentAlgorithm;

    public static $algorithms = array(
        'HS256' => array('hash_hmac', 'SHA256'),
        'HS512' => array('hash_hmac', 'SHA512'),
        'HS384' => array('hash_hmac', 'SHA384'),
        'RS256' => array('openssl', 'SHA256'),
    );

    /**
     * @param string $algorithm    The signing algorithm. Supported
     *                             algorithms are 'HS256', 'HS384' and 'HS512'
     * @param int $bufferTime    The time in seconds to account for clock skew
     */
    public function __construct($algorithm = 'HS256', $bufferTime = 0)
    {
        $this->useAlgorithm($algorithm);
        $this->allowBufferTime($bufferTime);
    }

    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string $jwt   The Json Web Token
     * @param string|Array|null $key    The secret key, or map of keys
     * @param Array $allowedAlgorithms  List of supported verification algorithms
     *
     * @return object   The Json Web Token's payload as a PHP object
     *
     * @uses jsonDecode
     * @uses urlsafeB64Decode
     */
    public function decode($jwt, $key = null, $allowedAlgorithms = array())
    {
        $tokenSegments = explode('.', $jwt);

        if (count($tokenSegments) != 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }

        list($header, $body, $crypto) = $tokenSegments;

        $header = $this->extractHeader($header);
        $payload = $this->extractPayload($body);
        $signature = $this->urlsafeB64Decode($crypto);

        if (isset($key)) {
            if (empty($header->alg)) {
                throw new DomainException('Empty algorithm');
            }

            $this->supportedAlgorithm($header->alg);
            $this->allowedAlgorithm($header->alg, $allowedAlgorithms);

            $key = $this->extractKey($key, $header);

            // Check the signature
            if (!$this->verify("$header.$body", $signature, $key, $header->alg)) {
                throw new SignatureInvalidException('Signature verification failed');
            }

            if ($this->tokenUseableNow($payload)) {
                throw new BeforeValidException(
                    'Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->nbf)
                );
            }

            if ($this->tokenCreatedBeforeNow($payload)) {
                throw new BeforeValidException(
                    'Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->iat)
                );
            }

            if ($this->tokenExpired($payload)) {
                throw new ExpiredException('Expired token');
            }
        }

        return $payload;
    }

    /**
     * Converts and signs a PHP object or array into a JWT string.
     *
     * @param object|array $payload    PHP object or array
     * @param string $key    The secret key
     * @param null $keyId
     *
     * @return string A signed JWT
     * @uses jsonEncode
     * @uses urlsafeB64Encode
     */
    public function encode($payload, $key, $keyId = null)
    {
        $header = array(
            'typ' => 'JWT',
            'alg' =>  $this->currentAlgorithmName()
        );

        if ($keyId !== null) {
            $header['kid'] = $keyId;
        }

        $signingInput = $this->generateSigningInput($header, $payload);

        return $this->generateSignature($signingInput, $key);
    }

    /**
     * Sign a string with a given key and algorithm.
     *
     * @param string $message    The message to sign
     * @param string|resource $key    The secret key
     *
     * @return string    An encrypted message
     * @throws DomainException    Unsupported algorithm was specified
     */
    public function sign($message, $key)
    {
        list($function, $algorithm) = $this->currentAlgorithmValues();

        switch($function) {
            case 'hash_hmac':
                return hash_hmac($algorithm, $message, $key, true);
            case 'openssl':
                $signature = '';
                $success = openssl_sign($message, $signature, $key, $algorithm);
                if (!$success) {
                    throw new DomainException("OpenSSL unable to sign data");
                } else {
                    return $signature;
                }
        }
    }

    /**
     * Verify a signature with the message, key and method. Not all methods
     * are symmetric, so we must have a separate verify and sign method.
     *
     * @param string $message    the original message
     * @param string $signature
     * @param string|resource $key    for HS*, a string key works. for RS*,
     *                                must be a resource of an openssl public key
     * @return bool
     */
    private function verify($message, $signature, $key)
    {
        list($function, $algorithm) = $this->currentAlgorithmValues();

        switch($function) {
            case 'openssl':
                $success = openssl_verify($message, $signature, $key, $algorithm);
                if (!$success) {
                    throw new DomainException("OpenSSL unable to verify data: " . openssl_error_string());
                } else {
                    return $signature;
                }
            case 'hash_hmac':
            default:
                $hash = hash_hmac($algorithm, $message, $key, true);
                if (function_exists('hash_equals')) {
                    return hash_equals($signature, $hash);
                }
                $length = min($this->safeStringLength($signature), $this->safeStringLength($hash));

                $status = 0;
                for ($i = 0; $i < $length; $i++) {
                    $status |= (ord($signature[$i]) ^ ord($hash[$i]));
                }
                $status |= ($this->safeStringLength($signature) ^ $this->safeStringLength($hash));

                return ($status === 0);
        }
    }

    /**
     * Decode a JSON string into a PHP object.
     *
     * @param string $input    JSON string
     *
     * @return object    Object representation of JSON string
     * @throws DomainException    Provided string was invalid JSON
     */
    public function jsonDecode($input)
    {
        if (version_compare(PHP_VERSION, '5.4.0', '>=') && !(defined('JSON_C_VERSION') && PHP_INT_SIZE > 4)) {
            /** In PHP >=5.4.0, json_decode() accepts an options parameter, that allows you
             * to specify that large ints (like Steam Transaction IDs) should be treated as
             * strings, rather than the PHP default behaviour of converting them to floats.
             */
            $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);
        } else {
            /** Not all servers will support that, however, so for older versions we must
             * manually detect large ints in the JSON string and quote them (thus converting
             *them to strings) before decoding, hence the preg_replace() call.
             */
            $maxIntLength = strlen((string) PHP_INT_MAX) - 1;
            $jsonWithoutBigInts = preg_replace('/:\s*(-?\d{' . $maxIntLength . ',})/', ': "$1"', $input);
            $obj = json_decode($jsonWithoutBigInts);
        }

        if (function_exists('json_last_error') && $errorCode = json_last_error()) {
            $this->handleJsonError($errorCode);
        } elseif ($obj === null && $input !== 'null') {
            throw new DomainException('Null result with non-null input');
        }
        return $obj;
    }

    /**
     * Encode a PHP object into a JSON string.
     *
     * @param object|array $input    A PHP object or array
     *
     * @return string    JSON representation of the PHP object or array
     * @throws DomainException    Provided object could not be encoded to valid JSON
     */
    public function jsonEncode($input)
    {
        $json = json_encode($input);
        if (function_exists('json_last_error') && $errorCode = json_last_error()) {
            $this->handleJsonError($errorCode);
        } elseif ($json === 'null' && $input !== null) {
            throw new DomainException('Null result with non-null input');
        }
        return $json;
    }

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input    A Base64 encoded string
     *
     * @return string    A decoded string
     */
    public function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padLength = 4 - $remainder;
            $input .= str_repeat('=', $padLength);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * Encode a string with URL-safe Base64.
     *
     * @param string $input    The string you want encoded
     *
     * @return string    The base64 encode of what you passed in
     */
    public function urlsafeB64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Helper method to create a JSON error.
     *
     * @param int $errorCode    An error number from json_last_error()
     *
     * @return void
     */
    private function handleJsonError($errorCode)
    {
        $messages = array(
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON'
        );
        throw new DomainException(
            isset($messages[$errorCode])
            ? $messages[$errorCode]
            : 'Unknown JSON error: ' . $errorCode
        );
    }

    /**
     * Get the number of bytes in cryptographic strings.
     *
     * @param string
     * @return int
     */
    private function safeStringLength($string)
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($string, '8bit');
        }
        return strlen($string);
    }

    /**
     * @param $algorithm
     * @return $this
     * @throws DomainException
     */
    public function useAlgorithm($algorithm)
    {
        $this->supportedAlgorithm($algorithm);

        $this->currentAlgorithm = array(
            'name' => $algorithm,
            'values' => self::$algorithms[$algorithm]
        );

        return $this;
    }

    /**
     * @param $algorithm
     * @throws DomainException
     */
    private function supportedAlgorithm($algorithm)
    {
        if (empty(self::$algorithms[$algorithm])) {
            throw new DomainException('Algorithm not supported');
        }
    }

    /**
     * @param $header
     * @return object
     */
    protected function extractHeader($header)
    {
        if (null === $header = $this->jsonDecode($this->urlsafeB64Decode($header))) {
            throw new UnexpectedValueException('Invalid header encoding');
        }

        return $header;
    }

    /**
     * @param $allowedAlgorithms
     * @param $algorithm
     */
    protected function allowedAlgorithm($algorithm, $allowedAlgorithms)
    {
        if (!is_array($allowedAlgorithms) || !in_array($algorithm, $allowedAlgorithms)) {
            throw new DomainException('Algorithm not allowed');
        }
    }

    /**
     * @param $body
     * @return object
     */
    protected function extractPayload($body)
    {
        if (null === $payload = $this->jsonDecode($this->urlsafeB64Decode($body))) {
            throw new UnexpectedValueException('Invalid claims encoding');
        }

        return $payload;
    }

    /**
     * @return mixed
     */
    private function currentAlgorithmName()
    {
        return $this->currentAlgorithm['name'];
    }

    /**
     * @return mixed
     */
    private function currentAlgorithmValues()
    {
        return $this->currentAlgorithm['values'];
    }

    /**
     * Extract the secret key using the header kid (Key ID)
     *
     * @param $key
     * @param $header
     * @return mixed
     * @throws DomainException
     */
    protected function extractKey($key, $header)
    {
        if (is_array($key) || $key instanceof ArrayAccess) {
            if (isset($header->kid)) {
                $key = $key[$header->kid];
                return $key;
            } else {
                throw new DomainException('"kid" empty, unable to lookup correct key');
            }
        }
        return $key;
    }

    /**
     * Check that this token has been created before 'now'. This prevents
     * using tokens that have been created for later use (and haven't
     * correctly used the nbf claim).
     *
     * @param $payload
     * @return bool
     */
    protected function tokenCreatedBeforeNow($payload)
    {
        return isset($payload->iat) && $payload->iat > (time() + $this->bufferTime);
    }

    /**
     * @param $header
     * @param $payload
     * @return string
     */
    private function generateSigningInput($header, $payload)
    {
        $encodedHeader = $this->urlsafeB64Encode($this->jsonEncode($header));
        $encodedPayload = $this->urlsafeB64Encode($this->jsonEncode($payload));

        return "$encodedHeader.$encodedPayload";
    }

    /**
     * @param $signingInput
     * @param $key
     * @return string
     */
    private function generateSignature($signingInput, $key)
    {
        $signature = $this->sign($signingInput, $key);
        $encodedSignature = $this->urlsafeB64Encode($signature);

        return "$signingInput.$encodedSignature";
    }

    /**
     * Check if the token has expired
     *
     * @param $payload
     * @return bool
     */
    protected function tokenExpired($payload)
    {
        return isset($payload->exp) && (time() - $this->bufferTime) >= $payload->exp;
    }

    /**
     * Check if the nbf if it is defined. This is the time that the
     * token can actually be used. If it's not yet that time, abort.
     *
     * @param $payload
     * @return bool
     */
    protected function tokenUseableNow($payload)
    {
        return isset($payload->nbf) && $payload->nbf > (time() + $this->bufferTime);
    }

    /**
     * @param int $bufferTime
     * @return $this
     */
    public function allowBufferTime($bufferTime)
    {
        $this->bufferTime = $bufferTime;

        return $this;
    }
}
