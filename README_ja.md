# mysqlproxy

MySQL Proxy server.

## Usage

設定ファイルを読み込む方法での使い方

### 親プロキシ側

```sh
./mysqlproxy -root -configpath=/path/to/config
```

### 子プロキシ側

```sh
# 従来通り
./mysqlproxy
```

```
接続方法
mysql -S /path/to/mysqlproxy.sock -u user1@192.168.1.1
mysql -S /path/to/mysqlproxy.sock -u user2@192.168.2.1


設定ファイル
["user1"]
username = "user1"
password = "******"
proxyserver = "192.168.1.1"

["user2"]
username = "user2"
password = "******"
proxyserver = "192.168.2.1"
```
