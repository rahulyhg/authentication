<?php
/**
 * Created by PhpStorm.
 * User: xiaoyu-tech
 * Date: 2019/3/21
 * Time: 11:59
 */

namespace Chaincszzz\Authentication;

class Authentication {
    /**
     * @var array
     *
     * 支持的认证方式
     */
    private $supportType = ['Basic', "Digest"];
    
    /**
     * @param $type
     *
     * @return bool
     *
     * 检查认证的类型
     */
    private function checkType($type) {
        return in_array($type, $this->supportType);
    }
    
    /**
     * @param $username
     * @param $password
     * @param $type
     * @param $realm
     *
     * @throws \Chaincszzz\Authentication\AuthenticationException
     *
     * 创建认证
     */
    public function createAuthentication($username, $password, $type, $realm="login") {
        if (!$this->checkType($type)) {
            throw new AuthenticationException("authentication type error is not support", 0);
        }
        
        switch ($type) {
            case "Basic":
                if (isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW']) && $username == $username && $_SERVER['PHP_AUTH_PW'] == $password) {
                    return TRUE;
                } else {
                    echo " header ";
                    header('WWW-Authenticate: Basic realm="' . $realm . '"'); // 弹出认证信息
                    header('HTTP/1.0 401 Unauthorized');
                }
                break;
            case "Digest":
                if(isset($_SERVER['PHP_AUTH_DIGEST'])){
                    $data   = $this->http_digest_parse($_SERVER['PHP_AUTH_DIGEST']);
                    $verify = $this->verify($data, $username, $password, $realm);
                    if (isset($_SERVER['PHP_AUTH_DIGEST']) && $data && $verify) {
                        return TRUE;
                    }
                }
                
                header('HTTP/1.1 401 Unauthorized');
                header('WWW-Authenticate: Digest realm="' . $realm . '",qop="auth",nonce="' . uniqid() . '",opaque="' . md5($realm) . '"');
                break;
        }
        
        return FALSE;
    }
    
    /**
     * @param        $username
     * @param        $password
     * @param        $type
     * @param string $realm
     *
     * @return bool
     * @throws \Chaincszzz\Authentication\AuthenticationException
     *
     * 校验输入
     */
    private function verify($data, $username, $password, $realm = '') {
        $A1             = md5($username . ':' . $realm . ':' . $password);
        $A2             = md5($_SERVER['REQUEST_METHOD'] . ':' . $data['uri']);
        $valid_response = md5($A1 . ':' . $data['nonce'] . ':' . $data['nc'] . ':' . $data['cnonce'] . ':' . $data['qop'] . ':' . $A2);
        if ($data['response'] != $valid_response) {
            return FALSE;
        } else {
            return TRUE;
        }
    }
    
    /**
     * @param $digest_data
     *
     * @return array|bool
     *
     * 解析digest数据
     */
    private function http_digest_parse($digest_data) {
        $needed_parts = array('nonce' => 1, 'nc' => 1, 'cnonce' => 1, 'qop' => 1, 'username' => 1, 'uri' => 1, 'response' => 1);
        $data         = array();
        $keys         = implode('|', array_keys($needed_parts));
        
        preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $digest_data, $matches, PREG_SET_ORDER);
        
        foreach ($matches as $m) {
            $data[ $m[1] ] = $m[3] ? $m[3] : $m[4];
            unset($needed_parts[ $m[1] ]);
        }
        
        return $needed_parts ? FALSE : $data;
    }
    
}