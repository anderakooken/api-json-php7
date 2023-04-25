<?php 
/*

Desenvolvedores: 
André Cavalcante, SYS.ENG. @anderakooken
Carla Nascimento, Q.A.

Descrição:

Instanciamento do pacote de objetos p/ acesso ao API
Para entendimento do processo, dentro do diretorio DIAGRAMA, 
é possivel encontrar o arquivos de sequenciamento de processos.

*/

namespace Szarca {

	error_reporting(0);
	
	#funções e ferramentas para auxiliar a aplicação
	include("objects.php");

	#classes instanciadas.

	use \DOMDocument;
	use Objects\main as Ferramentas;
	use Sources\Financeiro\main as Financeiro;
	use Sources\Industrial\main as Industrial;
	use Sources\Comercial\main as Comercial;
	use Sources\NTI\main as NTI;

	#carrega os arquivos de fontes
	Ferramentas::loadPackages();

	class main {

		/*
			Função de controle principal ao acesso as informações 
			das fontes, funciona como mediador, possibilitantando a 
			captura e relacionamento em tempo real.
		*/

		public static function middleware(string $i) : String {
			try {

				#Parametros recebidos
				$i = json_decode($i, true);

				#instancia da função de login do sistema
				$logonData = 
					Ferramentas::logon($i["logon"]["user"], $i["logon"]["passwd"]);
				
				if($logonData["type"] == false){
					return Ferramentas::report(false, $logonData["message"]);	exit();
				}

				#parametros obrigatorios
				if(!Ferramentas::isObjExist(isset($i["function"]))){
					return Ferramentas::report(false, "A função solicitada não existe");	exit();
				}

				#define o tipo de estrutura de saída da informação, xml, json etc.
				if(Ferramentas::isObjExist(isset($i["pattern"]))){

					#Se for informado pelo usuario, altera a variavel 
					Ferramentas::$pattern 	= $i["pattern"];
				}
				
				#Armazena os parametros de consulta
				Ferramentas::$function		= $i["function"];
				Ferramentas::$parameters 	= $i["param"];

				#Lista de funções e fontes
				$fn = Ferramentas::$function;

				$openUse = Ferramentas::use();


				if($openUse["type"]){
					return $openUse["message"];
				} else {
					return Ferramentas::report(false, $openUse["message"]);
				}

			} catch(Exception $e){
				return Ferramentas::report(false, "Erro no carregamento das informações");
			}
		}
	}

	header("Access-Control-Allow-Origin: *");
	header("Access-Control-Allow-Headers: *");
	header("Access-Control-Allow-Methods: POST");
	header('Content-Type: application/json; charset=utf-8');

	date_default_timezone_set('America/Fortaleza');

	$source = file_get_contents('php://input');

	#Instancia principal - Inicio da Aplicação
	if(Ferramentas::isObjExist(isset($source))){
		print main::middleware($source);
	} else {
		print Ferramentas::report(false, 
			array(
				"Warning" => "No parameters were received. Please authenticate."
				#"Do" => "You must use a json object to request information from the app. Replace ' to '' on Example.",
				#"Example" => "?source={'logon':{'user':'@example','passwd':'****','function':'example','param':{'param1':'value1'}}",
				)
			);
	}
}
?>