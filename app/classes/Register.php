<?php
namespace Auth;

use \Firebase\JWT\JWT;

class Register {
    /**
    *users first name
    *
    *@var string
    */

    private $first_name;

    /**
    *users last name
    *
    *@var string
    */

    private $last_name;

    /**
    *users email
    *
    *@var string
    */

    private $email;

    /**
    *users password
    *
    *@var string
    */

    private $password;

    /**
    *second password to confirm passwords match
    *
    *@var string
    */

    private $confirm_password;

    /**
    *token created if user if registered and authenticated successfully
    *
    *@var string
    */

    private $token;

    /**
    *database instance is stored in $conn property
    *
    *@var object
    */

    private $conn;

    public function __construct($first_name, $last_name, $email, $password, $confirm_password, $conn) {
        $this->first_name = trim($first_name);
        $this->last_name = trim($last_name);
        $this->email = trim($email);
        $this->password = trim($password);
        $this->confirm_password = trim($confirm_password);
        $this->conn = $conn;
    }

    /**
    *getter for token
    *
    *@return string
    */

    public function getToken() {
        return $this->token;
    }

    /**
    *method carries out validation before registration of user
    *
    *@return array
    */

    private function validate_registration_form() {
        $array = array();
        $errors = array();
        //set staus key to Success by default
        $array['status'] = "Success";

        //Check firstname lastname fields are not empty
        if(empty($this->first_name)) {
            $array['status'] = "Error";
            $errors[] = "-First name field is empty";
        }
        if(empty($this->last_name)) {
            $array['status'] = "Error";
            $errors[] = "-Last name field is empty";
        }
        //Check email field is not empty and that it is a valid email
        if(empty($this->email)) {
            $array['status'] = "Error";
            $errors[] = "-Email field is empty";
        } else if(!filter_var($this->email, FILTER_VALIDATE_EMAIL)) {
            $array['status'] = "Error";
            $errors[] = "-Email field does not contain a valid email";
        }

        //Check passwords match and not empty
        if($this->password != $this->confirm_password) {
            $array['status'] = "Error";
            $errors[] = "-Passwords do not match";
        } else if(empty($this->password)) {
            $array['status'] = "Error";
            $errors[] = "-Password field is empty";
        }
        //Return array to process whether there is an error or if validation is successful
        $array['errors'] = $errors;
        return $array;
    }

    /**
    *check if email already exists in datbaase
    *
    *@return array
    */

    private function verify_email() {
        $array = array();
        $errors = array();
        //Check if email already exists in users table
        try {
            $stmt = $this->conn->prepare("SELECT * FROM users WHERE email = :email");

            $stmt->bindParam(':email', $this->email);

            $stmt->execute();

            $results = array();

            while($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
                $results[] = $result;
            }

            //check result count, if 0 that means email doesnt exist so user can be registered
            if(count($results) == 0) {
                return $array['status'] = "Success";
            }

            //if count is not 0 that means the email address already exists so user cannot be registered
            $array['status'] = "Error";
            $errors[] = "-Email address already exists";
            $array['errors'] = $errors;
            return $array;

        } catch(\Exception $e) {
            $array['status'] = "Error";
            $errors[] = "Server Error";
            $array['errors'] = $errors;
            return $array;
        }

    }

    /**
    *generate token to log user in
    *
    *@return boolean
    */

    private function generate_token($payload) {
        try {
            $this->token = JWT::encode($payload, SECRET_KEY);
            return true;
        } catch(\Exception $e) {
            return false;
        }
    }

    /**
    *public method used to register the user in the API
    *
    *@return array
    */

    public function register_user() {
        //validate user input and store response
        $validate = $this->validate_registration_form();
        if($validate['status'] == "Error") {
            return $validate;
        }
        //make sure email does not already exist
        $verify = $this->verify_email();
        if($verify['status'] == "Error") {
            return $verify;
        }
        $array = array();
        try {
            $this->password = password_hash($this->password, PASSWORD_DEFAULT);

            $stmt = $this->conn->prepare("INSERT INTO users (first_name, last_name, email, password) VALUES(:first_name, :last_name, :email, :password)");

            $stmt->bindParam(':first_name', $this->first_name);
            $stmt->bindParam(':last_name', $this->last_name);
            $stmt->bindParam(':email', $this->email);
            $stmt->bindParam(':password', $this->password);

            $stmt->execute();

            $user_id = $this->conn->lastInsertId();
            $payload = array(
                "user" => $this->first_name,
                "id" => $user_id,
                "exp" => time()+2000,
            );

            $this->generate_token($payload);

            $array['status'] = "Success";
            return $array;

        } catch(\Exception $e) {
            $array['status'] = "Error";
            $errors[] = "Server Error";
            $array['errors'] = $errors;
            return $array;
        }

        $array['status'] = "Error";
        $errors[] = "Registration could not be completed";
        $array['errors'] = $errors;
        return $array;

    }
}
