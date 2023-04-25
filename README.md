# API-json-php7.4 

API que permite executar consultas em diversos bancos de dados relacionais (Oracle, SQLServer [...]) e retornar os resultados no formato JSON. A ideia do software é padronizar informações distribuídas e possibilitar o uso em programas de BI, tal como Power BI, SSIS ou Pentaho, por exemplo, ou para consumo em outras API.

## Softwares necessários

Sugiro utilizar o  **Apache ou Nginx** com **PHP 7.4**, pois essas versões são estáveis. Habilitar o uso de arquivos **.htaccess** também é importante para ocultar os diretórios e limitar os acessos sem autorização.  

## Estrutura do projeto

|Arquivo |                          |                         |
|----------------|-------------------------------|-----------------------------|
|objects.php| Classe / Funções | Lista funções do sistema
|index.php| Instância de classe / API           | As requisições devem ser enviadas para este arquivo |
|configuration/.config         | Configurações do programa            |   Caso utilize as configurações sem banco de dados    |
|configuration/.sql-mysql          |`Script SQL contendo a estrutura das tabelas`| Caso seja usado um banco de dados como configuração|

### index.php

Instância da função que recebe as requisições via HTTP.  A variável **$source** é o recebimento de texto puro **php://input** e a requisição deverá ser no formato JSON.
```php
main::middleware($source)
```
Exemplo de requisição:

```
curl --location --request POST 'http://[YOUR_IP]/szarca7.4/index.php' \
--header 'Content-Type: application/json' \
--data-raw '{
	"logon":
	{"user":"@admin","passwd":"3eaa2ac727c5bca6"},
	"function":"yourFunctionName",
	"param":{}
}'
```
|Parametro|                          |                         |
|----------------|-------------------------------|-----------------------------|
|user / passwd| usuário para solicitação de dados | Configurado no DB ou .config
|function| Função que trará as informações do DB
|param | Filtros que serão executados na consulta

### object.php

Arquivo que contem todas as funções e tratamentos utilizados no programa. 
Para iniciar o uso, é preciso decidir se o software utilizará um banco de dados para armazenamento das funções e usuários, ou esses dados serão armazenados estaticamente em um arquivo JSON.

```php
public static $pattern = "json"; 
private static $configFile = "";
```
|Variável|                          |                         |
|----------------|-------------------------------|-----------------------------|
|pattern| formato padrão de saída | 
|configFile| Arquivo de configuração estático em JSON  | Caso seja informado o arquivo **configuration/.config**, o acesso ao DB é desativado |

Caso seja optado pelo uso via DB, configure os dados da conexão:
```php
private static $dbSytemConfig = 
	array(
		"sgbd" => "mysql",
		"host" => "127.0.0.1",
		"port" => "3306",
		"schema" => "admin",
		"user" => "admin",
		"passwd" => "******"
	);
```
 
 ### .config

Caso seja optado pelo uso de arquivo estático:

```json
{
"system" : {
	"status" : true,
	"requestMethod" : "POST",
	"fileHeader" : true,
	"saveLogs" : false,
		"bruteForce" : {
		"status" : true,
		"hits" : 3
		},
	"cache" : {
		"database" : true
	},
	"plainTextRedirect" : false
},
"users" : [{
	"@admin" :{
		"id" : 1,
		"passwd":"3eaa2ac727c5",
		"status" : true,
			"data" : {
				"name" : "Admin",
				"phone" : 0,
				"email" : "admin@teste.com"
			},
		"security" : {
			"sources" : [
			"db-query"
			]
		}
	}
}],
"functions" :[{
	"db-query" : {
		"source" : "db-query",
		"query" : {
			"fileQueryText" : "",
			"queryText" : "",
			"parameters" : {
				"plainText" : true
			}
		},
	"setCache" : false,
	"cacheDuration" : 10,
	"status" : true
	}
}],
	"sources":[{
		"db-query" : {
			"sgbd" : "mysql",
			"host" : "127.0.0.1",
			"port" : 3306,
			"user" : "admin",
			"passwd" : "*******",
			"schema" :"admin"
		}
	}]
}
```