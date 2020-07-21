## 应用产品默认口令 {docsify-ignore}

?> 应用产品默认口令

?> 维护：[@atdpa4sword](https://github.com/atdpa4sw0rd)、[@r4v3zn](https://github.com/0nise)

### 堡垒机

!> 堡垒机，即在一个特定的网络环境下，为了保障网络和数据不受来自外部和内部用户的入侵和破坏，而运用各种技术手段监控和记录运维人员对网络内的服务器、网络设备、安全设备、数据库等设备的操作行为，以便集中报警、及时处理及审计定责。

| 厂商       | 产品                                                   | 口令        | FOFA Pro查询语法         | 备注                                                      |
| ---------- | ------------------------------------------------------ | ----------- | ------------------------ | --------------------------------------------------------- |
| Jumpserver | [JumpServer](https://github.com/jumpserver/jumpserver) | admin/admin | `app="Jumpserver堡垒机"` | [JumpServer Docs](https://docs.jumpserver.org/zh/master/) |

### 数据库应用

!> 数据库是“按照数据结构来组织、存储和管理数据的仓库“。是一个长期存储在计算机内的、有组织的、可共享的、统一管理的大量数据的集合。

| 厂商                 | 产品                                                         | 口令                                                         | FOFA Pro 查询语法         | 备注                                                         |
| -------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------- | ------------------------------------------------------------ |
| Oracle               | [Oracle](https://www.oracle.com/cn/database/)                | internal/oracle <br/>system/manager <br />sys/change_on_install <br />scott/tiger <br />scott/scott <br /> | `protocol="oracle"`       | scott 用户默认没有启用                                       |
| Oracle               | [MySQL](https://www.mysql.com/)                              | root/空 <br />root/root                                      | `protocol="mysql"`        |                                                              |
| Microsoft            | [Microsoft SQL Server](https://www.microsoft.com/en-au/sql-server) | sa/sa                                                        | `protocol="mssql"`        |                                                              |
| PostgreSQL           | [PostgreSQL](https://www.postgresql.org/)                    | postgres/空 <br />admin/admin                                | `app="PostgreSQL"`        |                                                              |
| MongoDB              | [MongoDB](www.mongodb.com)                                   | 无                                                           | `app="MongoDb"`           |                                                              |
| IBM                  | [IBM Db2]()                                                  | db2admin/db2admin <br />db2inst1/ibmdb2 <br />db2as/ibmdb2 <br />db2fenc1/ibmdb2 | `app="DB2数据库"`         | [IBM DB2通用数据库已知默认密码漏洞](https://www.anquanke.com/vul/id/1106115) |
| Elastic              | [Elasticsearch](https://www.elastic.co/cn/elasticsearch/)    | 无                                                           | `app="Elasticsearch"`     |                                                              |
| Salvatore Sanfilippo | [Redis](https://redis.io/)                                   | 无                                                           | `app="redis"`             |                                                              |
| SQLite               | [SQLite](https://www.sqlite.org/)                            | 无                                                           |                           |                                                              |
| Apache               | [Cassandra](https://cassandra.apache.org/)                   | 无                                                           | `protocol="cassandra"`    |                                                              |
| Microsoft            | [Access](https://www.microsoft.com/en-us/microsoft-365/access) | 无                                                           |                           |                                                              |
| MariaDB              | [MariaDB]()                                                  | root/空 <br />root/root                                      | `protocol="mysql"`        |                                                              |
| Splunk Inc.          | [Splunk](https://www.splunk.com/)                            | admin/changeme                                               | `app="Splunk"`            |                                                              |
| Apache               | [Hive](https://hive.apache.org/)                             | root/mine                                                    |                           |                                                              |
| Teradata             | [Teradata](https://www.teradata.com/)                        | dbc/dbc                                                      | `app="Teradata-公司产品"` |                                                              |
| Apache               | [Solr](https://lucene.apache.org/solr/)                      | 无                                                           | `app="Solr"`              |                                                              |

### 中间价应用

| 厂商      | 产品                                                | 口令                                               | FOFA Pro查询语法                                          | 备注                     |
| --------- | --------------------------------------------------- | -------------------------------------------------- | --------------------------------------------------------- | ------------------------ |
| Apache    | Tomcat                                              | admin/空                                           | `app="Tomcat默认页面"`                                    |                          |
| IBM       | WebSpher                                            | admin/admin                                        |                                                           |                          |
| Jboss     | Jboss                                               | admin/admin                                        |                                                           |                          |
| Apache    | Axis2                                               | admin/admin                                        |                                                           |                          |
| F5        | BIG-IP                                              | root/default <br />admin/default <br />admin/admin | `title="BIG-IP&reg;- Redirect" || icon_hash="-335242539"` | 首次登录后会强制修改密码 |
| portainer | [portainer](https://github.com/portainer/portainer) | admin/tryportainer                                 | `app="Portainer"`                                         |                          |



## 参考

- [DB-Engines Ranking](https://db-engines.com/en/ranking)

