# PHP Authentication

PHP Authentication Support Basic Authentication and Digest Authentication

### install
```
composer require chaincszzz/authentication
```

### usage
直接在需要进行认证的位置添加以下代码，代码会自动进行校验
```
$type = 'Basic'; // 支持Basic 、Digest
$authentication = new \Chaincszzz\Authentication\Authentication();
$res = $authentication->createAuthentication("username","password",$type);
```