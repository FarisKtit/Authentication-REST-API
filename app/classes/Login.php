<?php
namespace Auth;

class Login {

    /**
    *Email address of user
    *
    *@var string
    */

    private $email;

    /**
    *Password of user
    *
    *@var string
    */

    private $password;

    /**
    *User record from database
    *
    *@var array
    */

    private $user_data;

    /**
    *Store user token which is retrieved via getter to return to authenticated user
    *
    *@var string
    */

    private $token;

    /**
    *Store database connection
    *
    *
    */

    private $conn;

    public function __construct($email, $password, $conn) {
        $this->email = trim($email);
        $this->password = trim($password);
        $this->conn = $conn;
    }

    /**
    *Getter to retrieve user token that was generated when user is logged in
    *
    *@return string
    */

    public function getToken() {
        return $this->token;
    }

    /**
    *Check if user email exists
    *
    *@return boolean
    */

    private function verify_email() {
        $array = array();
        $errors = array();

        //query database to check if user email exists
        $stmt = $this->conn->prepare("SELECT * FROM users WHERE email = :email");

        $stmt->bindParam(':email', $this->email);

        //if statement successfully executes, check record count, otherwise return false
        $stmt->execute();

        $results = array();
        while($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            $results[] = $result;
        }

        if(count($results) === 1) {
            //results count is one so email exists thus user account exists
            $this->user_data = $results;
            $array['status'] = "Success";
            return $array;
        }

        $array['status'] = "Error";
        $errors[] = "Account does not exist";
        $array['errors'] =  $errors;
        return $array;
    }

    /**
    *Check if password supplied by user matches password on user record
    *
    *@return boolean
    */

    private function verify_password() {
        $array = array();
        $errors = array();
        if(password_verify($this->password, $this->user_data[0]['password'])) {
            $array['status'] = "Success";
            return $array;
        }
        $array['status'] = "Error";
        $errors[] = "Password is incorrect";
        $array['errors'] = $errors;
        return $array;
    }

    /**
    *Create encrypted JSON web token with user details if successfully logged in
    *
    *@return boolean
    */

    private function generate_token($payload) {
        $array = array();
        $errors = array();
        try {
            $this->token = \Firebase\JWT\JWT::encode($payload, SECRET_KEY);
            $array['status'] = "Success";
        } catch(\Exception $e) {
            $array = array();
            $array['status'] = "Error";
            $errors[] = "Server error";
            $array['errors'] = $errors;
        } finally {
            return $array;
        }
    }

    /**
    *Log user in method which utilises other methods in the class
    *
    *@return boolean
    */

    public function login_user() {
        $array = array();
        try {
            //verify email and password
            $array = $this->verify_email();
            if($array['status'] == "Error") {
                return $array;
            }
            $array = $this->verify_password();
            if($array['status'] == "Error") {
                return $array;
            }
            //if email and password successfully verified, set token on token property and return true
            $payload = array(
                "user" => $this->user_data[0]['first_name'],
                "id" => $this->user_data[0]['id'],
                "exp" => time()+2000,
            );
            $token = $this->generate_token($payload);
            if($token['status'] == "Error") {
                return $token;
            }

            $array['status'] = "Success";
        } catch(\Exception $e) {
            $array['status'] = "Error";
            $errors[] = "Server Error";
            $array['errors'] = $errors;

        } finally {
            return $array;
        }


    }
}
