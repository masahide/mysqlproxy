# mysqlproxy

MySQL Proxy server.

## Usage

### Connect to MySQL Server via MySQL proxy server

MySQL Proxy サーバーを経由してのMySQL接続方法

```
mysql -S /path/to/mysqlproxy.sock -u <MySQLサーバーのユーザー名>@<MySQLサーバーのホスト>(:<MySQLサーバーのポート>)
※ ポートが3306番であれば省略可能
```


### Starting MySQL proxy server (root)

クライアントから接続するためのデーモン

```
./mysqlproxy -root
```

### Starting MySQL proxy server

MySQLサーバーに中継するためのデーモン

```
./mysqlproxy
```

### PHP Sample

```php
$link = mysql_connect(
	'/path/to/mysqlproxy.sock',
	'<db user>:<db password>@<proxy host>:<proxy port>;<db host>:<db port>',
	'<db password>',
);

// For example in following Data flow.

// Connect to A
$link = mysql_connect(
	':/path/to/mysqlproxy.sock',
	'user_a:******@192.168.1.1:9696;192.168.1.2:3306',
	'******',
);

// Connect to B
$link = mysql_connect(
	':/path/to/mysqlproxy.sock',
	'user_b:******@192.168.1.1:9696;192.168.1.3:3306',
	'******',
);

// Connect to C
$link = mysql_connect(
	':/path/to/mysqlproxy.sock',
	'user_c:******@192.168.2.1:9696;192.168.2.2:3306',
	'******',
);

// Connect to D
$link = mysql_connect(
	':/path/to/mysqlproxy.sock',
	'user_d:******@192.168.2.1:9696;192.168.2.3:3306',
	'******',
);
```

### Data flow

```
           Unix domain socket   TLS                       TCP
           Connect              Connect                   Connect
+--------+      +-------------+      +------------------+      +------------------+
| mysql  | ---> | mysql proxy | -+-> | mysql proxy      | -+-> | mysql server     |
| client |      | (root)      |  |   |                  |  |   | (A)              |
| (PHP)  |      | localhost   |  |   | 192.168.1.1:9696 |  |   | 192.168.1.2:3306 |
+--------+      +-------------+  |   +------------------+  |   +------------------+
                                 |                         |                      
                                 |                         |   +------------------+
                                 |                         +-> | mysql server     |
                                 |                             | (B)              |
                                 |                             | 192.168.1.3:3306 |
                                 |                             +------------------+
                                 |                                                
                                 |   +------------------+      +------------------+
                                 +-> | mysql proxy      | -+-> | mysql server     |
                                     |                  |  |   | (C)              |
                                     | 192.168.2.1:9696 |  |   | 192.168.2.2:3306 |
                                     +------------------+  |   +------------------+
                                                           |                      
                                                           |   +------------------+
                                                           +-> | mysql server     |
                                                               | (D)              |
                                                               | 192.168.2.3:3306 |
                                                               +------------------+
```

