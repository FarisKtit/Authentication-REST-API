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
    $data['message'] = "Server Error";
    echo JSON_encode($data);
    return;
}

if($_SERVER['REQUEST_METHOD'] == "POST") {
    $data = json_decode(file_get_contents('php://input'), true);

    if($data['type'] == "register") {
        $registration = new Auth\Register($data['first_name'], $data['last_name'], $data['email'], $data['password'], $data['confirm_password'], $conn);
        $response = $registration->register_user();
        if($response['status'] == "Success") {
            $response['token'] = $registration->getToken();
        }
        echo JSON_encode($response);
        return;
    }
}
