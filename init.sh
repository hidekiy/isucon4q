#!/bin/sh
set -x
set -e
cd $(dirname $0)

myuser=root
mydb=isu4_qualifier
myhost=127.0.0.1
myport=3306
mysql -h ${myhost} -P ${myport} -u ${myuser} -e "DROP DATABASE IF EXISTS ${mydb}; CREATE DATABASE ${mydb}"
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/schema.sql
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/dummy_users.sql
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/dummy_log.sql
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/ban_ip.sql
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/ban_user.sql
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/last_login.sql

sudo /etc/init.d/memcached restart
sudo /etc/init.d/supervisord restart
sleep 10
