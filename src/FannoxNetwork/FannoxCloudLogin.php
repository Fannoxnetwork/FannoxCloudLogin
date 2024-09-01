<?php
/**
 * FannoxNetwork Management System...
 *
 * @package   Fannox Cloud - FannoxNetwork 
 * @author    Team FannoxNetwork <team@fannoxnetwork.com>
 * @copyright (C) FannoxNetwork Management Systems  
 * @license   https://fannoxnetwork.com/license/
 * @link      https://fannoxnetwork.com/products/
 */

namespace FannoxNetwork;

use Exception;

class FannoxCloudLogin {
    private $clientId;
    private $clientSecret;
    private $redirectUri;
    private $baseUrl;
    private $state;

    public function __construct($clientId, $clientSecret, $redirectUri) {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->redirectUri = $redirectUri;
        $this->baseUrl = "http://localhost/fannox";
    }

    public function redirectToLogin() {
        $this->state = bin2hex(random_bytes(16)); // Secure random state for CSRF protection
        $_SESSION['oauth_state'] = $this->state;

        $authUrl = $this->baseUrl . "/oauth/authorize?" . http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'state' => $this->state,
        ]);

        header("Location: $authUrl");
        exit;
    }

    public function handleCallback() {
        if (isset($_GET['code'], $_GET['state'], $_GET['lid'])) {

            $lid = $_GET['lid'];

            $authorizationCode = $_GET['code'];

            $tokenData = $this->exchangeToken($authorizationCode, $lid);

            if (isset($tokenData['access_token'])) {
                return $this->fetchUserData($tokenData['access_token'], $lid);
            } else {
                throw new Exception("Failed to retrieve access token. Error: " . ($tokenData['error_description'] ?? 'Unknown error'));
            }
        } else {
            throw new Exception("Invalid state or missing authorization code.");
        }
    }

    public function encrypt_user_id($user_id) {
        $encryption_key = 'your_secret_key'; // Replace with a secure key
        return openssl_encrypt($user_id, 'AES-128-ECB', $encryption_key);
    }   

    public function decrypt_user_id($encrypted_user_id) {
        $encryption_key = 'your_secret_key'; // Same key used for encryption
        return openssl_decrypt($encrypted_user_id, 'AES-128-ECB', $encryption_key);
    }

    private function exchangeToken($code, $lid) {
        $tokenUrl = $this->baseUrl . "/oauth/token";
        $postData = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'lid' => $lid,
            'redirect_uri' => $this->redirectUri,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        $response = $this->sendPostRequest($tokenUrl, $postData);
        $decodedResponse = json_decode($response, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Failed to parse token response: " . json_last_error_msg());
        }

        if (isset($decodedResponse['error'])) {
            throw new Exception("OAuth Error: " . $decodedResponse['error'] . " - " . ($decodedResponse['error_description'] ?? 'No description provided'));
        }

        return $decodedResponse;
    }

    private function fetchUserData($accessToken, $lid) {
        $userInfoUrl = $this->baseUrl . "/api/userinfo";

        $ch = curl_init($userInfoUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            "Authorization: Bearer $accessToken",
            "logId: $lid"
        ]);
        $response = curl_exec($ch);

        file_put_contents('debug.log', "User Data Raw Response: " . $response . PHP_EOL, FILE_APPEND);

        if (curl_errno($ch)) {
            throw new Exception("cURL error: " . curl_error($ch));
        }

        curl_close($ch);

        return json_decode($response, true);
    }

    private function sendPostRequest($tokenUrl, $postData) {
        $ch = curl_init($tokenUrl);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $tokenResponse = curl_exec($ch);

        if (curl_errno($ch)) {
            throw new Exception("cURL error: " . curl_error($ch));
        }

        curl_close($ch); 
        return $tokenResponse;
    }
}

?>
