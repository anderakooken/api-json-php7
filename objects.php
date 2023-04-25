<?php 

/*

Desenvolvedores: 
André Cavalcante, SYS.ENG. @anderakooken
Carla Nascimento, Q.A.

Descrição:

Pacote p/ gerenciar o API p/ multiplas bases de dados:

- Funções de conexão com base de dados ou arquivo de texto
- Opções de cache com temporização 
- Controle de acessos de usuarios, endereço ip,  aplicações e origem de dados
- Armazenamento de logs
- Controle de acesso bruto

*/

namespace Objects
{

	error_reporting(0);
	
	use \PDO;
	use \PDOException;
	use \SimpleXMLElement;
	use \DateTime;
	use \DateTimeZone;
	use Sources\main as Fonte;
	use Objects\main as Ferramentas;

	class main {

		public static $function;
		public static $parameters;
		public static $userSecurity = array();
		public static $userLogged = array();
		public static $pattern = "json"; #default pattern
		private static $configFile = ""; #arquivo de banco de dados em JSON (configuration/.config)

		private static $dbSytemConfig = array(
			"sgbd"	 	=> "mysql",
			"host" 		=> "127.0.0.1",
			"port" 		=> "3306",
			"schema" 	=> "szarca",
			"user" 		=> "szarca",
			"passwd" 	=> "sz!2020_Mdware"
		);

		private static $properties = 
				array(
					"name"			=>"Szarca",
					"architecture"	=>"json",
					"version"		=>"7.0",
					"administrator"	=>"Szarca Administrator"
				);
		
		#carregamento dos arquivos necessarios 
		public static function loadPackages(){}

		public static function use() : Array {
			
			self::setLog(
				array(
					"type" => "requestData",
					"contents" => array(
						"user" => self::$userLogged["login"], 
						"function" => self::$function,
						"parameters" => self::$parameters
					)
				)
			);

			#abre o arquivo de configurações
			$arrayJson = self::openConfig();

			#retorno padrão
			$return  = array("type" => false, "message" => "a funcao selecionada nao existe");

			for($i=0;$i <= count($arrayJson["functions"]); $i++){
				if(isset($arrayJson["functions"][$i][self::$function])){		

					#seleciona a função
					$fn = $arrayJson["functions"][$i][self::$function];

					#verifica se a função esta ativada
					if($fn["status"]){

						#Verifica se a função permite controlar a função da fonte de forma externa
						#o usuario poderá alterar os parametros da função pre-definida
						$plainText = false;
						if(isset($fn["query"]["parameters"])){
							if(isset($fn["query"]["parameters"]["plainText"])){
								$plainText = $fn["query"]["parameters"]["plainText"];
							}
						}

						if($plainText == false){

							#Se for especificado no arquivo config. p/ URL
							if($fn["query"]["queryText"]){

								$queryText = $fn["query"]["queryText"];

							} else {
								#get by file -fazer a função pra abrir arquivo externo
								$fileQueryText = self::$function;

								if(isset($fn["query"]["fileQueryText"])){
									if($fn["query"]["fileQueryText"]){
										$fileQueryText = $fn["query"]["fileQueryText"];
									}
								}

								$fileSQL = "queries/".($fileQueryText).".sql";

								if(file_exists($fileSQL)){
									
									$sqlText = "";
									$storedSQL = fopen($fileSQL, "r");
									while(!feof($storedSQL)) {
										$sqlText .= fgets($storedSQL);
									}
									fclose($storedSQL);

									$queryText = $sqlText;
								}
							}
						}

						$sqlParameters = self::isParameter();

						if(isset($fn["query"]["parameters"])){
							if($fn["query"]["parameters"]){
								$sqlParameters = $fn["query"]["parameters"];
							}	
						}
						$return  = 
							array(
								"type" => true, 
								"message" => 
									self::pattern(self::$pattern, 
									self::query(
										array(
											"source" => $fn["source"], 
											"query" => 
												self::queryReport(
													true, $queryText
												),
											"plainTextParameters" => $plainText,
											"parameters" => array(
												"execute"=>true,
												"vars"=>$sqlParameters
											)
										)
									)
								)
							);
						
						break;

					} else {

						$return  = array("type" => false, "message" => "a funcao selecionada foi desabilitada pelo administrador");
						break;
					}
					
				}
			}

			return $return;
			exit();
		}

		#captura os cabeçalhos de requisição 
		public static function getHeader() : String {
			$headers = apache_request_headers();
			foreach ($headers as $header => $value) {
				 $data .= $header .":". $value;
			}
			return $data;
		}

		#verifica a direnca entre dois dias (data)
		public static function dateDifference($a, $b) : Int{
			
			$diff = strtotime($b) - strtotime($a);
			$result = floor($diff / (60 * 60 * 24));

			 return $result;
		}

		public static function doQuery(array $p) : Array{
			return 
				self::query(array(
					"source" => $p["source"], 
					"query" => self::queryReport(true, $p["query"]),
					"plainTextParameters" => "",
					"parameters" => array(
						"execute"=>true,
						"vars"=> $p["vars"]
						)
					)
				);
		}

		#ativa o brute force
		public static function setBruteForce(array $data) : Array {
			try {
			
				#abre o arquivo de configurações
				$arrayJson = self::openConfig();

				#verifica se esta configurado pra salvar
				if($arrayJson["system"]["bruteForce"]["status"]){

					#salva uma linha de log antecipado, para relatorios futuros
					if($data["updateHit"] == true){
						self::doQuery(
							array(
								"source" => "system", 
								"query" => "INSERT INTO bruteForceLogs 
									(`user_id`, `user`, `ip`, `plainText`, `date`) 
										VALUES 
									(:uid, :usr, :ip, :txt, :dt)",
								"vars" => array(
									"uid" => $data["idUser"], 
									"usr" => $data["login"],
									"ip" => $_SERVER["REMOTE_ADDR"],
									"txt" => base64_encode(self::getHeader()),
									"dt" => date("Y-m-d H:i:s")
								)
							)
						);
					}

					#verifica a contagem
					$search = 
						self::doQuery(
							array(
								"source" => "system", 
								"query" => "SELECT * FROM bruteForce WHERE user_id = :uid",
								"vars" => array("uid" => $data["idUser"])
							)
						);
					
					#verifica se já houve algum registro referente ao usuario
					if(isset($search["resultset"][0])){

						#verifica a diferença entre o ultimo log x dia atual
						$diffTime = self::dateDifference(
							date("Y-m-d"), 
							date("Y-m-d", strtotime($search["resultset"][0]["date"]))
						);

						#ainda nas 24h da primeira tentativa
						if($diffTime == 0){

							#comando p/ atualizar o contador de hits
							$SQL = "UPDATE bruteForce SET `count` = (`count` + 1) WHERE user_id = :uid";
							$SQLP = array("uid" => $data["idUser"]);

							#verifica se atingiu o numero de tentativas
							if($search["resultset"][0]["count"] >= $arrayJson["system"]["bruteForce"]["hits"]){
								$return = array(
									"type" => true, 
									"message" => "usuario bloqueado pelo bruteforce"
								);
							} else {
								$return = array(
									"type" => false, 
									"message" => "usuario não está bloqueado"
								);
							}

						} else {

							#se não estiver dentro da diferença entre dias configurados
							$SQL = "UPDATE bruteForce SET `count` = 0, `date` = :dt WHERE user_id = :uid";
							$SQLP = array("uid" => $data["idUser"], "dt" => date("Y-m-d H:i:s"));

							$return = array(
								"type" => false, 
								"message" => "usuario não está bloqueado"
							);
						}

						#atualiza a contagem, CASO seja opção
						if($data["updateHit"] == true){
							$setDiff = 
							self::doQuery(
								array(
									"source" => "system", 
									"query" => $SQL,
									"vars" => $SQLP
								)
							);
						}
						

					} else {
						
						#insere a primeira contagem
						$setDiff = 
							self::doQuery(
								array(
									"source" => "system", 
									"query" => "INSERT INTO bruteForce (`user_id`, `count`, `date`) VALUES (:uid, '0', :dt)",
									"vars" => array(
										"uid" => $data["idUser"], 
										"dt" => date("Y-m-d H:i:s")
									)
								)
							);
						
						$return = array(
							"type" => false, 
							"message" => "arquivo logBruteForce atualizado"
						);
					}
				} else {
					$return = array(
						"type" => false, 
						"message" => "verifique as configurações para bruteForce"
					);
				}
				
			} catch (\Exception $e){
				$return = array(
					"type" => false, 
					"message" => "erro interno ao salvar o logBruteForce"
				);
			}
			
			return $return;

		}
		public static function setLog(array $data) : Array {

			try {
			
				#abre o arquivo de configurações
				$arrayJson = self::openConfig();

				if($arrayJson["system"]["saveLogs"]){

					$fileLog = "logs/".$data["contents"]["user"]."-".date("Ymd-His")."_R".rand(0,999999).".json";

					file_put_contents($fileLog, 
						self::jsonEncode(
							array(
								"header" => self::getHeader(),
								"date" => date("Y-m-d H:i:s"),
								"contents" => $data["contents"]
							)
						)
					);

					if(file_exists($fileLog)){
						$return = array(
							"type" => true, 
							"message" => "arquivo de log"
						);
					} else {
						$return = array(
							"type" => false, 
							"message" => "não foi possivel salvar arquivo de log"
						);
					}
				} else {
					$return = array(
						"type" => false, 
						"message" => "não foi possivel salvar arquivo de log"
					);
				}
				
			} catch (\Exception $e){
				$return = array(
					"type" => false, 
					"message" => "erro interno ao salvar o log"
				);
			}
			
			return $return;

		}
		public static function setCache(array $data) : Array {

			try {
				
				#abre o arquivo de configurações
				$arrayJson = self::openConfig();

				#verifica se esta configurado pra salvar
				if($arrayJson["system"]["cache"]["database"]){

					#print_r($returned);
					$returned = self::doQuery(
						array(
							"source" => "system", 
							"query" => "INSERT INTO storedCache 
								(`function`, `user_id`, `user_login`, `date`, `file`) 
									VALUES 
								(:fn, :uid, :usr, :dt, :txt)",
							"vars" => array(
								"fn" 	=> self::$function, 
								"uid" 	=> self::$userLogged["id"],
								"usr" 	=> self::$userLogged["login"],
								"dt" 	=> date("Y-m-d H:i:s"),
								"txt" 	=> base64_encode(self::jsonEncode($data))
							)
						)
					);

					$return = array(
						"type" => true, 
						"message" => "arquivo de cache salvo"
					);

				} else {

					$fileCache = "cache/".(self::$function).".json";
				
					file_put_contents($fileCache, self::jsonEncode($data));
	
					if(file_exists($fileCache)){
						$return = array(
							"type" => true, 
							"message" => "arquivo de cache salvo"
						);
					} else {
						$return = array(
							"type" => false, 
							"message" => "não foi possivel salvar arquivo de cache"
						);
					}

				}
				
			} catch (\Exception $e){
				$return = array(
					"type" => false, 
					"message" => "erro interno ao salvar o cache"
				);
			}
			
			return $return;

		}
		private static function issetCacheFile() : Array{
			
			$cacheConfigExists = false;
			$fileCache = "cache/".(self::$function).".json";

			#abre o arquivo de configurações
			$arrayJson = self::openConfig();

			#resposta padrão
			$return = array(
				"type"=>false, 
				"cache" => 
					array(
						"setCache"  => false
					),
				"message"=> "arquivo não possui configuração de cache"
			);
			
			#Verifica se a função solicitada possui configurações
			# de cache e duração (em minutos)
			for($i=0;$i <= count($arrayJson["functions"]); $i++){
				if(isset($arrayJson["functions"][$i][self::$function])){		

					#seleciona a função
					$fn = $arrayJson["functions"][$i][self::$function];

					#armazena os parametros caso a função possua cache
					if($fn["setCache"] == true){
						$cacheConfigExists = true;
						$duration = $fn["cacheDuration"];
					}
				}
			}
			
			#verifica se o arquivo esta válido em cache
			#a regra é segurar a consulta durante a duração estipulada

			if($cacheConfigExists == true){

				#verifica se esta configurado pra salvar no banco de dados
				if($arrayJson["system"]["cache"]["database"]){

					#se for banco de dados
					#verifica se existe o arquivo na tabela
					$search = 
					self::doQuery(
						array(
							"source" => "system", 
							"query" => 
								"SELECT * FROM 
									storedCache WHERE 
										`user_id` = :uid and 
										`function` = :fn 
									ORDER BY id DESC 
									LIMIT 0,1
								",
							"vars" => array(
								"fn" 	=> self::$function, 
								"uid" 	=> self::$userLogged["id"]
							)
						)
					);

					#verifica se já houve algum registro referente ao usuario
					if(isset($search["resultset"][0])){

						$initialDate = $search["resultset"][0]["date"];
						$durationTime = "+ ".$duration." minutes"; 
	
						$dateReturn = strtotime($initialDate . $durationTime);

						#se data atual for menor que o prazo de validade
						if(date("YmdHis") <= date('YmdHis', $dateReturn)){

							#retorna o arquivo de cache p/ leitura
							$return = 
							array(
								"type"=> true,
								"cache" => 
									array(
										"setCache"  => false,
										"fileDate"=> $initialDate,
										"expirationDate" => date('Y-m-d H:i:s', $dateReturn)
									),
								"message"=> 
									json_decode(
										base64_decode($search["resultset"][0]["file"])
									)
							);

						} else {
	
							#arquivo vencido
							$return = 
								array(
									"type"=> false, 
									"cache" => 
										array(
											"setCache"  => true,
											"fileDate"=> $initialDate,
											"expirationDate" => date('Y-m-d H:i:s', $dateReturn)
										),
									"message"=> "arquivo vencido"
								);
						}

					}  else {
						#arquivo não existe, precisa criar
						$return = 
							array(
								"type"=> false, 
								"cache" => 
										array(
											"setCache"  => true,
										),
								"message"=> "arquivo ainda não existe"
							);
					}

				} else {

					#se for arquivo de dados
					if (file_exists($fileCache)) {
					
						$initialDate = date ("Y-m-d H:i:s", filemtime($fileCache));
						$durationTime = "+ ".$duration." minutes"; 
	
						$dateReturn = strtotime($initialDate . $durationTime);
	
						#se data atual for menor que o prazo de validade do arquivo
						if(date("YmdHis") <= date('YmdHis', $dateReturn)){
	
							#ler e disponibiliza p/ usuario
							$jsonFile = "";
							$cache = fopen($fileCache, "r");
							while(!feof($cache)) {
								$jsonFile .= fgets($cache);
							}
							fclose($cache);
	
							#retorna o arquivo de cache p/ leitura
							$return = 
								array(
									"type"=> true,
									"cache" => 
										array(
											"setCache"  => false,
											"fileDate"=> $initialDate,
											"expirationDate" => date('Y-m-d H:i:s', $dateReturn)
										),
									"message"=> json_decode($jsonFile)
								);
	
						} else {
	
							#arquivo vencido
							$return = 
								array(
									"type"=> false, 
									"cache" => 
										array(
											"setCache"  => true,
											"fileDate"=> $initialDate,
											"expirationDate" => date('Y-m-d H:i:s', $dateReturn)
										),
									"message"=> "arquivo vencido"
								);
						}
					} else {
						#arquivo não existe, precisa criar
						$return = 
							array(
								"type"=> false, 
								"cache" => 
										array(
											"setCache"  => true,
										),
								"message"=> "arquivo ainda não existe"
							);
					}
				}
			}

			return $return;
		}

		private static function jsonEncode(array $in) : String {
			return json_encode($in, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE |  JSON_UNESCAPED_SLASHES);
		}

		#Captura as informações do usuario logado
		public static function userData(array $data) : String {
			return 
				Ferramentas::pattern(
					Ferramentas::$pattern, 
						array(
							"source" => "configuration", 
							"resultset"=>$data
						)
				);
		}

		private function openConfigDatabase(string $SQL) : Array {

			#se for pelo banco de dados
			$opt = array(
				PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES UTF8',
				PDO::ATTR_ERRMODE, 
				PDO::ERRMODE_EXCEPTION
			);

			try{
				
				$connObj = new PDO(
					self::$dbSytemConfig["sgbd"].':'.
					'host='.self::$dbSytemConfig["host"].';'.
					'port='.self::$dbSytemConfig["port"].';'.
					'dbname='.self::$dbSytemConfig["schema"].'', 
					self::$dbSytemConfig["user"], 
					self::$dbSytemConfig["passwd"], 
				$opt);
		
				$statement = $connObj->prepare($SQL);
				$statement->execute(array());
				$results = $statement->fetchAll(PDO::FETCH_ASSOC);

			} catch(\PDOException $e){
				print Ferramentas::report(false, 
					array(
						"Warning" => "O database de configuração está offline. Contate o administrador imediatamente."
						#"Do" => "You must use a json object to request information from the app. Replace ' to '' on Example.",
						#"Example" => "?source={'logon':{'user':'@example','passwd':'****','function':'example','param':{'param1':'value1'}}",
						)
					);
			}
			

			return $results;
		}

		private function intToBool($i){
			return (boolval($i) ? 'true' : 'false');
		}
		#arquivo de configurações, atua como mini-base de dados 
		private function openConfig() : Array{

			if(self::$configFile){

				return self::$configFile;
				
			} else {

				#se for um arquivo JSON fixo
				if(self::$configFile){

					$jsonFile = file_get_contents(self::$configFile);
					$arrayJson = json_decode($jsonFile, true);

					self::$configFile = $arrayJson;

				} else {
					
					#montagem do arquivo JSON via banco de dados
				
					$config["system"] = self::openConfigDatabase("SELECT * FROM configuration")[0];
					$config["sources"] = self::openConfigDatabase("SELECT * FROM sources");
					$config["functions"] = self::openConfigDatabase("
					
						SELECT 
						srs.name as source,
						fn.*  
						from 
							functions fn
							left join sources srs ON fn.sources_id = srs.id
					
					");
					$config["users"] = self::openConfigDatabase("SELECT u.* FROM users u ORDER BY u.id");
					$config["uas"] = self::openConfigDatabase("SELECT * FROM securityUserAgent");
					$config["adrs"] = self::openConfigDatabase("SELECT * FROM securityAddress");
					$config["srs"] = self::openConfigDatabase("
						SELECT s.users_id, src.* FROM 
							securitySources s
						LEFT JOIN sources src ON src.id = s.sources_id
					");
					

					#print_r($config["uas"]);
					#exit();

					$JSON .=
						'"system" : {
							"status" : '.self::intToBool($config["system"]["status"]).',
							"requestMethod" : "'.$config["system"]["requestMethod"].'",
							"fileHeader" : '.self::intToBool($config["system"]["fileHeader"]).',
							"saveLogs" : '.self::intToBool($config["system"]["saveLogs"]).',
							"bruteForce" : {
								"status" : '.self::intToBool($config["system"]["bruteForceStatus"]).',
								"hits" : '.(int)$config["system"]["bruteForceHits"].'
							},
							"cache" : {
								"database" : '.self::intToBool($config["system"]["database"]).'
							},
							"plainTextRedirect" : '.self::intToBool($config["system"]["plainTextRedirect"]).'
						},'
					;

					$totalSources = count($config["sources"]);
					for($i=0;$i<$totalSources;$i++){
						if($i != ($totalSources - 1)){$comma = ",";	} else {$comma = "";	}
						$srs .=	'"'.$config["sources"][$i]["name"].'" : {
							"sgbd" : "'.$config["sources"][$i]["sgbd"].'",
							"host" : "'.$config["sources"][$i]["host"].'",
							"port" : "'.$config["sources"][$i]["port"].'",
							"user" : "'.$config["sources"][$i]["user"].'",
							"passwd" : "'.$config["sources"][$i]["passwd"].'",
							"schema" :"'.$config["sources"][$i]["schema"].'"
						}'.$comma;
					}
					$JSON .= '"sources":[{'.$srs.'}],';

					$totalfunctions = count($config["functions"]);
					for($i=0;$i<$totalfunctions;$i++){
						if($i != ($totalfunctions - 1)){$comma = ",";	} else {$comma = "";	}
						$fns .=	'
							"'.$config["functions"][$i]["name"].'" : {
								"source" : "'.$config["functions"][$i]["source"].'",
								"query" : {
									"fileQueryText" : "'.$config["functions"][$i]["fileQueryText"].'",
									"queryText" : "'.str_replace('"',"%22",$config["functions"][$i]["queryText"]).'",
									"parameters" : {
										"plainText" : '.self::intToBool($config["functions"][$i]["plainText"]).'
									}
								},
								"setCache" : '.self::intToBool($config["functions"][$i]["setCache"]).',
								"cacheDuration" : '.$config["functions"][$i]["cacheDuration"].',
								"status" : '.self::intToBool($config["functions"][$i]["status"]).'
							}'.$comma;
					}
					$JSON .= '"functions":[{'.$fns.'}],';

					
					#useragents dos usuarios
					$totalUA = count($config["uas"]);
					for($i=0;$i<$totalUA;$i++){
						if($i != ($totalUA - 1)){$comma = ",";	} else {$comma = "";	}

						$sec[$config["uas"][$i]["users_id"]]["userAgent"] .= '{
							"description" : "'.$config["uas"][$i]["description"].'",
							"type":"'.$config["uas"][$i]["type"].'",
							"app":"'.$config["uas"][$i]["app"].'"
						},';

					}

					#endereços de ip dos usuarios
					$totalAddr = count($config["adrs"]);
					for($i=0;$i<$totalAddr;$i++){
						if($i != ($totalAddr - 1)){$comma = ",";	} else {$comma = "";	}

						$sec[$config["adrs"][$i]["users_id"]]["ipAddress"] .= '{
							"description" : "'.$config["adrs"][$i]["description"].'",
							"type":"'.$config["adrs"][$i]["type"].'",
							"ip":"'.$config["adrs"][$i]["ip"].'"
						},';

					}

					#sources liberados para usuarios
					$totalSrc = count($config["srs"]);
					for($i=0;$i<$totalSrc;$i++){
						if($i != ($totalSrc - 1)){$comma = ",";	} else {$comma = "";	}

						$sec[$config["srs"][$i]["users_id"]]["sources"] .= '"'.$config["srs"][$i]["name"].'",';

					}

					#lista de usuarios
					$totalUsers = count($config["users"]);
					for($i=0;$i<$totalUsers;$i++){
						if($i != ($totalUsers - 1)){$comma = ",";	} else {$comma = "";	}

							$usrs .=	'
							"'.$config["users"][$i]["login"].'" : 
							{
								"id" : '.$config["users"][$i]["id"].',
								"passwd":"'.$config["users"][$i]["hash"].'",
								"status" : '.self::intToBool($config["users"][$i]["status"]).',
								"data" : {
									"name" : "'.$config["users"][$i]["name"].'",
									"phone" : "'.$config["users"][$i]["phone"].'",
									"email" : "'.$config["users"][$i]["email"].'" 
								}, 
								"security" : {
									"ipAddress":[
										'.substr($sec[$config["users"][$i]["id"]]["ipAddress"],0,-1).'
									],
									"userAgent":[
										'.substr($sec[$config["users"][$i]["id"]]["userAgent"],0,-1).'
									],
									"sources" : [
										'.substr($sec[$config["users"][$i]["id"]]["sources"],0,-1).'
									]
								}
							}'.$comma;

					}

					$JSON .= '"users":[{'.$usrs.'}]';
					$JSON = "{".$JSON."}";
				
					$arrayJson = json_decode($JSON, true);

					self::$configFile = $arrayJson;

					return self::$configFile;
					
				}
			}
		}

		#verifica as limitações por ip
		private static function logonSecurity(array $cmd) : Array {

			#pega os dados armazenados do usuario logado
			$sec = self::$userSecurity;

			#resposta padrão
			$return = array("type"=>true, "message"=> "");

			if(isset($sec)){
				if(isset($sec[$cmd["option"]])){
					for($a=0;$a <= count($sec[$cmd["option"]]); $a++){
	
						# => Verifica se existe bloqueios p/ navegador do usuario ---------------]
						# [----------------------------------------------------------------------]
						if($cmd["option"] == "userAgent"){

							#se houver alguma regra estabelecida, o padrão é bloqueio
							$return = 
								array(
									"type"=>false, 
									"message"=> "usuario possui restrições não estabelecidas para este app."
								);

							if(isset($sec[$cmd["option"]][$a]["type"])){
								
								#verifica se libera todos os apps
								if($sec[$cmd["option"]][$a]["app"] == "*"){
									
									$return = array(
										"type"=>true, 
										"message"=> "Todos os apps estão liberados"
									);
	
									break;

								} else {

									if(strstr(strtolower($_SERVER['HTTP_USER_AGENT']), strtolower($sec[$cmd["option"]][$a]["app"]))){
										if($sec[$cmd["option"]][$a]["type"] == "deny"){
			
											$return = array(
												"type"=>false, 
												"message"=> "usuario não possui permissao para requisições neste app."
											);
			
											break;
										}
										if($sec[$cmd["option"]][$a]["type"] == "accept"){
			
											$return = array(
												"type"=>true, 
												"message"=> ""
											);
			
											break;
										}
									} 
								}
							}
						}

						# => Verifica se existe bloqueios p/ IP no usuario ---------------------------]
						# [---------------------------------------------------------------------------]
						if($cmd["option"] == "ipAddress"){

							#se houver alguma regra estabelecida, o padrão é bloqueio
							$return = 
								array(
									"type"=>false, 
									"message"=> "usuario possui restrições não estabelecidas para este endereço"
								);

							if(isset($sec[$cmd["option"]][$a]["type"])){
								
								#verifica se libera todos os ips
								if($sec[$cmd["option"]][$a]["ip"] == "*"){
									
									$return = array(
										"type"=>true, 
										"message"=> "Todos os Endereços estão liberados"
									);
	
									break;

								} else {

									if($sec[$cmd["option"]][$a]["ip"] == $_SERVER["REMOTE_ADDR"]){
										if($sec[$cmd["option"]][$a]["type"] == "deny"){
			
											$return = array(
												"type"=>false, 
												"message"=> "usuario não possui permissao para requisições neste endereço"
											);
			
											break;
										}
										if($sec[$cmd["option"]][$a]["type"] == "accept"){
			
											$return = array(
												"type"=>true, 
												"message"=> ""
											);
			
											break;
										}
									}
								}
							}
						}

						#verifica se usuario possui permissao de acesso a fonte de dados
						if($cmd["option"] == "sources"){

							#resposta padrão é negativa, pois é permissional
							$return = 
								array(
									"type"=>false, 
									"message"=> "o usuario não possui permissao para a fonte solicitada"
								);

							if(isset($sec[$cmd["option"]][$a])){

								#verifica se libera todos os sources
								if($sec[$cmd["option"]][$a] == 0){
									
									$return = array(
										"type"=>true, 
										"message"=> "Todos os sources estão liberados"
									);
	
									break;

								} else {
									if($sec[$cmd["option"]][$a] == $cmd["value"]){

										$return = array(
											"type"=> true, 
											"message"=> "usuario possui permissao"
										);
		
										break;
									}
								}
							}
						}
					}
				}
			}
			return $return;
		}

		#Login do sistema
		public static function logon($user, $passwd) : Array {

			#Verifica os usuarios do sistema no arquivo de configuração
			$arrayJson = self::openConfig();

			$return = array(
				"type"=>false, 
				"message"=> "credenciais incorretas, acesso negado. use um arquivo JSON."
			);
			
			$idUsr;

			for($i=0;$i <= count($arrayJson["users"]); $i++){
				if(isset($arrayJson["users"][$i][$user])){		

					$usr = $arrayJson["users"][$i][$user];
					$idUsr = $usr["id"];

					if($usr["status"]){

						#bruteForce, verifica se usuario está bloqueado
						$bruteForceRequest = self::setBruteForce(array("idUser" => $idUsr, "login" => $user));

						if($bruteForceRequest["type"] == true){
							
							$return = array(
								"type"=>false, 
								"message"=> $bruteForceRequest["message"]
							);

							break;
						}

						if($usr["passwd"] == $passwd){

							#armazena os dados se segurança do usuario
							if(isset($usr["security"])){
								self::$userSecurity = $usr["security"];
							}

							#-------------------------------------------------------------------
							#instancia p/ segurança - verifica se o navegador está permitido
							$ua_securityArray = 
								self::logonSecurity(
									array("option" => "userAgent")
								);
							#verifica as limitações por IP do usuario
							if($ua_securityArray["type"] == false){
								$return = array(
									"type"=>false, 
									"message"=> $ua_securityArray["message"]
								);
								break;
							} 

							#-------------------------------------------------------------------
							#instancia p/ segurança
							$securityArray = 
								self::logonSecurity(
									array("option" => "ipAddress")
								);

							#verifica as limitações por IP do usuario
							if($securityArray["type"] == false){
								$return = array(
									"type"=>false, 
									"message"=> $securityArray["message"]
								);
								break;
							} 

							#-------------------------------------------------------------------
							#mensagem de retorno (dados do usuario, com exceção da senha)
							$return = array(
								"type"=>true, 
								"message"=> 
									array(
										"data" => $usr["data"],
										"security"=>self::$userSecurity
									)
								);

							#dados basicos do usuario p/ serem exibidos nas consultas de retorno
							#a intenção é saber o usuario que consultou
							self::$userLogged = 
								array(
									"login" => $user,
									"id" => $usr["id"],
									"name"=>$usr["data"]["name"],
									"email"=> $usr["data"]["email"],
								);

							break;

						} else {

							#bruteForce
							self::setBruteForce(array("idUser" => $idUsr, "login" => $user, "updateHit" => true ));

							break;

						}
					} else {

						$return = array("type"=>false, 
							"message"=> "credenciais desabilitadas pelo administrador."
						);

						break;
					}
				}
			}

			return $return;
		}

		#padrões de conexões diversas
		private static function connection(array $src) : Array {
			
			$arrayJson = self::openConfig();

			#Os retornos deverão ser exibidos em formatação UTF8 (acentuados)
			$opt = array(
				PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES UTF8',
				PDO::ATTR_ERRMODE, 
				PDO::ERRMODE_EXCEPTION
			);

			#lista as fontes de dados
			for($i=0;$i <= count($arrayJson["sources"]); $i++){

				#seleciona a fonte solicitada
				if(isset($arrayJson["sources"][$i][$src["source"]])){					

					$srs = $arrayJson["sources"][$i][$src["source"]];

					try {

						#SE FOR UM JSON ORIUNDO DE URL SIMPLES
						if($srs["sgbd"] == "url-json"){

							try{
								
								$contentFile = file_get_contents($srs["host"]."?".$src["query"]);
								if($contentFile == true){

									$connObj = trim(stripslashes(html_entity_decode($contentFile)));
									$connObj = json_decode(preg_replace('/[\x00-\x1F\x80-\xFF]/', '', $connObj), true);

									if(!$connObj){
										$return = array("type"=>false,"message"=>"retorno fora do padrão JSON");
										break;
									}
									
									$return = 
										array(
											"type"=>true,
											"message"=> array(
												"isSGBD" => false,
												"returnObj" => ($connObj)
											)
										);
									
									break;
									
								} else {
	
									$return = array("type"=>false,"message"=>"fonte de dados não acessível.");
									break;
								}

							}catch(Exception $e){
								$return = array("type"=>false,"message"=>"fonte de dados não acessível.");
								break;
							}

						} 

						#SE FOR UM ARQUIVO plainText ARMAZENADO NO DATALAKE
						if($srs["sgbd"] == "plainText"){

							$contentFile = file_get_contents($src["query"]);

							if($contentFile == true){

								$return = 
									array(
										"type"=>true,
										"message"=> array(
											"isSGBD" => false,
											"returnObj" => array(
												"encoded"=>"base64",
												"plainTextParameters" => $src["query"],
												"value" => base64_encode(preg_replace('/[\x00-\x1F\x80-\xFF]/', '', $contentFile))
											)
										)
									);
								
								break;
								
							} else {

								$return = array("type"=>false,"message"=>"fonte de dados não acessível.");
								break;
							}

						}

						#SE FOR UM XML ORIUNDO DE URL SIMPLES
						if($srs["sgbd"] == "url"){

							if($src["plainTextParameters"] == false){
								$openURL = $srs["host"]."?".$src["query"];
								$plainTextURL = "";
							} else {
								$openURL = $srs["host"]."?".urldecode(self::$parameters["plainText"]);
								$plainTextURL = urldecode(self::$parameters["plainText"]);
							}

							$contentFile = file_get_contents($openURL);
							if($contentFile == true){

								$return = 
									array(
										"type"=>true,
										"message"=> array(
											"isSGBD" => false,
											"returnObj" => array(
												"encoded"=>"base64",
												"plainTextParameters" => $plainTextURL,
												"value" => base64_encode(preg_replace('/[\x00-\x1F\x80-\xFF]/', '', $contentFile))
											)
										)
									);
								
								break;
								
							} else {

								$return = array("type"=>false,"message"=>"fonte de dados não acessível.");
								break;
							}
						}


						#SGBD - MYSQL SERVER
						if($srs["sgbd"] == "mysql"){
							$connObj = new PDO(
								$srs["sgbd"].':'.
								'host='.$srs["host"].';'.
								'port='.$srs["port"].';'.
								'dbname='.$srs["schema"].'', 
								$srs["user"], 
								$srs["passwd"], 
							$opt);
						}
	
						#SGBD - ORACLE 11G ou superior
						if($srs["sgbd"] == "oracle"){
							$connObj = new PDO('oci:dbname='.$srs["host"].'/'.$srs["schema"].'', 
								$srs["user"], $srs["passwd"], $opt);
						}
	
						$return = 
								array(
									"type"=>true,
									"message"=> array(
										"isSGBD" => true,
										"returnObj" => $connObj
									)
								);

						#$return = array("type"=>true,"message"=> $connObj);
	
						break;
	
					} catch(PDOException $e){
						$return = array("type"=>false,"message"=>"fonte de dados não acessível.");
					} 
				}
			}
			return $return;
		}

		#consulta a fonte de informação
		public static function query(array $in) : Array {
			try {
	
				$SQL = $in["query"]["return"];

				#instancia p/ segurança, verifica se possui 
				#permissao para a fonte de dados

				#se for consultas do proprio sistema
				if($in["source"] == "system"){
				
					$src = self::connection(
						array(
							"source" => $in["source"],
							"query" => $SQL["message"],
							"plainTextParameters" => $in["plainTextParameters"]
						)
					);

					#importante! a saída padronizadas das colunas são em lowercase
					$src["message"]["returnObj"]->setAttribute(PDO::ATTR_CASE, PDO::CASE_LOWER);
												
					$statement = $src["message"]["returnObj"]->prepare($SQL["message"]);

					$defaultParameters = array();
					if($in["parameters"]["execute"]){
						$defaultParameters = $in["parameters"]["vars"];
					}

					$statement->execute($defaultParameters);
					$results = $statement->fetchAll(PDO::FETCH_ASSOC);

					#retorno (data)
					$rtnData["parameters"] = $in["parameters"];

					return 
						array(
							"function"=> Ferramentas::$function,
							"source" => $in["source"], 
							"parameters" => $rtnData["parameters"], 
							"cache" => 
								array("type"=> false),
									"resultset"=>$results
							);

				} else {
				
				#demais consultas do sistema

					$securityArray = 
						self::logonSecurity(
							array(
								"option" => "sources",
								"value" => $in["source"]
							)
						);
				
					if($SQL["type"] == true){
						if($securityArray["type"] == true){

							#Verifica se o arquivo está na regra de cache
							$issetCache = self::issetCacheFile();

							#se não possuir arquivo de cache, então realiza a consulta online
							if($issetCache["type"] == false){

								$src = self::connection(
										array(
											"source" => $in["source"],
											"query" => $SQL["message"],
											"plainTextParameters" => $in["plainTextParameters"]
										)
									);
							
								if($src["type"] == true){

									#se for uma conexão p/ um SGBD
									if($src["message"]["isSGBD"] == true){

										#importante! a saída padronizadas das colunas são em lowercase
										$src["message"]["returnObj"]->setAttribute(PDO::ATTR_CASE, PDO::CASE_LOWER);
												
										$statement = $src["message"]["returnObj"]->prepare($SQL["message"]);

										$defaultParameters = array();
										if($in["parameters"]["execute"]){
											$defaultParameters = $in["parameters"]["vars"];
										}

										$statement->execute($defaultParameters);
										$results = $statement->fetchAll(PDO::FETCH_ASSOC);

										#retorno (data)
										$rtnData["parameters"] = $in["parameters"];
									} else {
										
										#retorno (data)
										$rtnData["parameters"] = array();
										$results = $src["message"]["returnObj"];
									}
									

									#se estiver programado para gerar cache
									if($issetCache["cache"]["setCache"] == true){

										#escreve o aquivo de cache
										$cacheReturn = self::setCache($results);

									}

									return 
										array(
											"function"=> Ferramentas::$function,
											"source" => $in["source"], 
											"parameters" => $rtnData["parameters"], 
											"cache" => 
												array(
													"type"=> false
												),
											"resultset"=>$results
										);
								
								} else {
									return Ferramentas::queryReport(false, "fonte de dados não acessível.");
								}
							} else {

								#se for (true)
								#abre o arquivo no cache
								return 
									array(
										"function"=> Ferramentas::$function,
										"source" => $in["source"], 
										"parameters" => $in["parameters"], 
										"cache" => 
											array(
												"type"=> true, 
												"fileDate" => $issetCache["cache"]["fileDate"],
												"expirationDate" => $issetCache["cache"]["expirationDate"]
											),
										"resultset"=> $issetCache["message"]
									);

							}
							
						} else {

							#
							#Caso os parametros obrigatorios não forem informados
							#Retorna com as informações de feedback da função de origem
							#
							return Ferramentas::queryReport(false, $securityArray["message"]);

						}
						

					} else {

						/*
						Caso os parametros obrigatorios não forem informados
						Retorna com as informações de feedback da função de origem
						*/
						return Ferramentas::queryReport(false, $SQL["message"]);
					}
				}
				
			} catch(PDOException $e) {
				return 'ERROR: ' . $e->getMessage();
			}
		}

		#verifica se contem valor operavel
		public static function isObjExist(string $v) : Bool {
			if($v == true){
				return true;
			} else {
				return false;
			}
		}

		/*
		verifica se parametros de filtros na consulta foram informados. 
		Se não, aplica-se uma matriz declarada.
		*/
		public static function isParameter() : Array {

			$p = self::$parameters;

			if(!is_array($p)){
				return $p = array();
			} else { return $p;}
		}

		#padrões de saída da informação
		#Recebe a string da consulta e sai JSON
		public static function pattern(String $p, Array $e) : String {

			date_default_timezone_set("America/Fortaleza");
			
			if($p == "json"){
				$out = array(
					"system" => self::$properties,
					"return" => array(
						"type" => (bool) "true",
						"ipAddress" => $_SERVER["REMOTE_ADDR"],
						"date"=> date("Y-m-d H:i:s"),
						"user"=>self::$userLogged,
						"message" => $e
						)
					
				);
				return self::jsonEncode($out); 
			}
		}

		#reporte de falhas ou avisos de consultas personalizadas que envolvam montagem
		#Retorna ARRAY
		public static function queryReport(bool $t, $message) : Array {
			$out = array(
				"return" => array(
					"type" => (bool) $t,
					"message" => $message
				)
			);
			return $out; 
		}

		#reporte de falhas ou avisos de sucesso do app
		public static function report(bool $t, $message) : String {
			$out = array(
				"system" => self::$properties,
				"return" => array(
					"type" => (bool) $t,
					"message" => $message
				)
			);
			return self::jsonEncode($out); 
		}
	}
}

?>