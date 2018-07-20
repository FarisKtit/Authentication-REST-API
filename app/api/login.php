<?php

require_once '../../vendor/autoload.php';
use \Firebase\JWT\JWT;


header('Access-Control-Allow-Origin: *');

define("SECRET_KEY", "example_key");

try {
    $db = new Auth\Database();
    $conn = $db->connect();
} catch(PDOException $e) {
    $data = array();
    $data['status'] = "Error";
    echo JSON_encode($data);
}

if($_SERVER['REQUEST_METHOD'] === "POST") {
    $data = json_decode(file_get_contents('php://input'), true);

    if($data['type'] === "login") {
        $login = new Auth\Login($data['email'], $data['password'], $conn);
        $response = $login->login_user();
        if($response['status'] == "Success") {
            $response['token'] = $login->getToken();
        }
        echo JSON_encode($response);
    }
}
