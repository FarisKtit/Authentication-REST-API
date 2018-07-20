<?php
namespace Auth;

class Database {
    //Database Parameters
    private $host;
    private $db_name;
    private $username;
    private $password;
    private $conn;

    //Constructor

    public function __construct() {
      $data = parse_ini_file('./../../config.php');
      $this->host = $data['host'];
      $this->db_name = $data['db_name'];
      $this->username = $data['username'];
      $this->password = $data['password'];
    }
    //Connect to Database
    public function connect() {
        $this->conn = null;

        try {
            $this->conn = new \PDO('mysql:host='.$this->host.';dbname='.$this->db_name, $this->username, $this->password);
            $this->conn->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        } catch(\PDOException $e) {
            $data = array();
            $data['status'] = "Error";
            echo JSON_encode($data);
        }

        return $this->conn;
    }
}
