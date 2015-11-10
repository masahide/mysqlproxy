<?php
// Connecting, selecting database
$link = mysql_connect(
	':/path/to/mysqlproxy.sock',
	'db_user:db_password@proxy_host:proxy_port;db_host:db_port',
	'proxy_password'
) or die('Could not connect: ' . mysql_error());
echo 'Connected successfully';
mysql_select_db('db_name') or die('Could not select database');

// Performing SQL query
$query = 'SELECT * FROM table_name';
$result = mysql_query($query) or die('Query failed: ' . mysql_error());

while ($line = mysql_fetch_array($result, MYSQL_ASSOC)) {
    echo $line['column_name'] . PHP_EOL;
}

// Free resultset
mysql_free_result($result);

// Closing connection
mysql_close($link);
