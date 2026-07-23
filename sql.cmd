CREATE DATABASE userkepdb;

USE userkepdb;

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(64),
    passwd VARCHAR(64),
	domain VARCHAR(256),
	priv_key VARCHAR(128),
	pub_key VARCHAR(128),
	sign_key VARCHAR(128),
	main_key VARCHAR(128),
	is_banned VARCHAR(8),
	is_admin VARCHAR(8),
    verified BOOL
);

:: 添加管理员
INSERT INTO users (
    name,
    passwd,
    domain,
    priv_key,
    pub_key,
    sign_key,
    main_key,
    is_banned,
    is_admin,
    verified
) VALUES (
    'user123',
    'ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f',
    'example.com',
    'a2V5MTIz...',
    'a2V5MTIz...',
    'a2V5MTIz...',
    'a2V5MTIz...',
    '',
    'admin',
    true
);

添加user123为admin，密码为12345678

'a2V5MTIz...'为key的base64，使用`kep-cli gen`后打开genkey.log获取3个key的base64，以及打开pkey.priv获取中间的私钥base64填上去

password需要先获取sha256
如'12345678'的sha256为
ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f