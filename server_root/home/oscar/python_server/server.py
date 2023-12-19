#!/usr/bin/env python3
# coding=utf-8

# Logger para imprimir mensajes de depuración.
import logging
# Librearía para extraer los argumentos de la línea de comandos.
import argparse
# Librería para interactuar con el sistema operativo y el entorno.
import sys, os
# Librería para trabajar con sockets.
import socket
# Libreria para seleccionar sockets listos para recibir datos.
import selectors
# Librería para comprobar expresiones regulares.
import re
# Librería para trabajar con fechas y horas.
import datetime

# - Óscar Vera López: DNI: 48840910L -> XXYY = 0910

# Dominio del servidor.
SERVER_NAME = "web.alterra0910.org"

# Correo electrónico del administrador del servidor.
ADMIN_EMAIL = "email=oscar.veral%40um.es"

# Tamaño de los buffers de lectura y escritura de datos en el socket.
BUFSIZE = 8192
# Segundos máximos de espera para recibir datos en el socket. Equivale a: X1+X2+Y1+Y2+10.
TIMEOUT_CONNECTION = 20
# Cookie que permite saber la cantidad de peticiones realizadas por un cliente a index.html. Formato: "cookie_counter_XXYY"
COOKIE_CONTROL_ACCESOS = "cookie_counter_0910"
# Tiempo de vida de la cookie de control de acceso en segundos.
MAX_AGE = 120
# Cantidad máxima de peticiones exitosas que puede realizar un cliente al recurso index.html.
MAX_ACCESOS_LANDING = 10
# Cantidad mínima de peticiones que puede realizar un cliente.
MIN_ACCESOS_LANDING = 1
# Constante para indicar que la cookie de control no es necesaria para la petición.
NO_COOKIE = None

# Constante para indicar la cantidad total de accesos permitidos en una conexión.
MAX_ACCESOS_TOTAL = 25

# Constantes para indicar resultados de ejecución.
ERROR = 1
SUCCESS = 0

# Constantes para el análisis de peticiones.
HTTP_VERSION = "HTTP/1.1"
VALID_METHODS = ["GET", "POST"]
ROOT_RESOURCE = "/"
LANDING_PAGE = "index.html"
BODY_SEPARATOR = "\r\n"
# Constantes para el análisis y construcción de cabeceras.
COOKIE_HEADER = "Cookie"
HOST_HEADER = "Host"

# Tipos de contenido admitidos por el servidor.
filetypes = {
	"gif"   :"image/gif", 
	"jpg"   :"image/jpg", 
	"jpeg"  :"image/jpeg", 
	"png"   :"image/png", 
	"htm"	:"text/htm", 
	"html"	:"text/html", 
	"css"	:"text/css", 
	"js"	:"text/js"
}

# Diccionario que correlaciona status codes con mensajes de respuesta.
status_codes = {
	200: "OK",
	400: "Bad Request",
	401: "Unauthorized",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	408: "Request Timeout",
	415: "Unsupported Media Type",
	429: "Too Many Requests",
	500: "Internal Server Error",
	505: "HTTP Version Not Supported"
}

# Expresión regular para la línea de petición.
re_request = re.compile(r'^(?P<method>[A-Z]{1,10}) (?P<path>/.*) (?P<version>HTTP/[0-9].[0-9])$') # TODO Quitar partes opcionales de la URL
re_header = re.compile(r'^(?P<nombre>[^:]+):( )?(?P<valor>.+)( )?$')

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()

def send_data(cs: socket.socket, data: bytes):
	# Enviamos todos los datos a través del socket cs y delvolvemos la cantidad de bytes enviados. Puede provocar excepciones.
	cs.send(data)
	return len(data)


def recv_data(cs: socket.socket):
	# Recibimos datos a través del socket cs y los devolvemos. Puede provocar excepciones.
	data = cs.recv(BUFSIZE)
	return data

def encode(data: str):
	# Esta función codifica un string en bytes.
	try:
		raw_data = data.encode()
		return raw_data
	except UnicodeEncodeError:
		return None
	

def decode(data: bytes):
	# Esta función decodifica bytes en un string.
	try:
		decoded_data = data.decode()
		return decoded_data
	except UnicodeDecodeError:
		return None
	

def cerrar_conexion(cs: socket.socket) -> None:
	# Cerrar el socket dado.
	cs.close()
	

def parse_data(data: str): 
	# Dividimos la petición en body y headers para después extraer la solicitud de los headers.
	data_list = data.split("\r\n\r\n")
	metadata = data_list[0].split("\r\n")
	# Extraemos los componentes del mensaje.
	request = metadata[0]
	if len(metadata) > 1:
		headers = metadata[1:]
	else:
		headers = []
	if len(data_list) > 1:
		body = data_list[1]
	else:
		body = ""
	# Devolvemos la tupla calculada.
	return (request, headers, body)



def parse_request(request_line: str):
	# Comprobamos la línea de petición contra nuestra expresión regular.
	request_match = re_request.fullmatch(request_line)
	
	# Si no coincide la expresión regular se retorna None para indicar una mala solicitud.
	if request_match is None:
		return None

	# Si coincide extraemos las partes y las devolvemos para que sean tratadas.
	method = request_match.group('method')
	path = request_match.group('path')
	version = request_match.group('version')
	return (method, path, version)


def build_absolute_path (webroot: str, resource_path: str):
	# Analizamos si se está pidiendo index.html, en otro limpiamos el path de parámetros. Finalmente construimos la ruta absoluta.
	if resource_path is ROOT_RESOURCE:
		resource_path = LANDING_PAGE
	else:
		resource_path = resource_path.split('?')[0].split('#')[0]
	resource_path = webroot + resource_path
	return resource_path


def parse_headers (headers):
	try:
		# Analizamos los headers para obtener un diccionario con estos y una lista de cookies.
		header_dict = {}
		cookie_list = []
		for header in headers:
			header_match = re_header.fullmatch(header)
			# No verificar el regex es un error de formato.
			if header_match is None:
				return None
			# Si es una cookie la metemos en la lista y si es otro header lo ponemos en el diccionario.
			if header_match.group('nombre') == COOKIE_HEADER:
				cookie_list.append(header_match.group('valor'))
			else:
				header_dict[header_match.group('nombre')] = header_match.group('valor')
		return (header_dict, cookie_list)
	# Un error de índice indica que no se ha podido parsear un header.	
	except IndexError:
		return None


def check_headers(headers, cs: socket.socket):
	# Imprimimos todas las cabeceras recibidas y comprobamos que se ha recibido la cabecera Host.
	result= False
	logger.debug("[Addr {}] Headers:".format(cs.getpeername()))
	for header in headers:
		logger.debug("[Addr {}]\t {}: {}".format(cs.getpeername(), header, headers[header]))
		if header == HOST_HEADER and headers[header].startswith(SERVER_NAME):
			result = True
	return result


def check_cookies(cookies,  cs: socket.socket):
	# Comprobar si la cookie cookie_counter existe.
	logger.debug("[Addr {}] Cookies:".format(cs.getpeername()))
	for cookie in cookies:
		logger.debug("[Addr {}]\t Cookie: {}".format(cs.getpeername(), cookie))
		if cookie.startswith(COOKIE_CONTROL_ACCESOS):
			logger.debug("[Addr {}]\t Cookie {} found!".format(cs.getpeername(), COOKIE_CONTROL_ACCESOS))
			value = int(cookie.split("=")[1])
			# Comprobar si el valor de la cookie está en el rango permitido. Si es así, incrementar el valor en 1 y devolverlo.
			if MIN_ACCESOS_LANDING <= value < MAX_ACCESOS_LANDING:
				logger.debug("[Addr {}]\t Cookie {} value {} is in range! Counter is now {}".format(cs.getpeername(), COOKIE_CONTROL_ACCESOS, value, value + 1))
				return value + 1
			# Si no, devolver MAX_ACCESOS
			logger.debug("[Addr {}]\t Cookie {} has max value {}!")
			return MAX_ACCESOS_LANDING
	# Si no existe la cookie, devolver MIN_ACCESOS como valor inicial.
	logger.debug("[Addr {}]\t Cookie {} not found! Counter stablished at {}".format(cs.getpeername(), COOKIE_CONTROL_ACCESOS, MIN_ACCESOS_LANDING))
	return MIN_ACCESOS_LANDING


def get_resource_type(path: str):
	# Extraemos la extensión del archivo y devolvemos el tipo de recurso correspondiente.
	try:
		extension = filetypes[os.path.basename(path).split('.')[1]]
		return extension
	
	except IndexError:
		return None


def get_resource_size(path: str):
	# Devolvemos el tamaño del recurso en bytes. Se asume una ruta válida de parámetro.
	return os.stat(path).st_size


def build_response_line(status_code: int):
	# Construimos la línea de estado de la respuesta.
	return  "HTTP/1.1 {} {}\r\n".format(status_code, status_codes[status_code])


def build_response_headers(resource_type: str, resource_size: int, cookie_value):
	# Construimos las cabeceras de la respuesta.
	headers = "Content-Type: {}\r\n".format(resource_type)
	headers += "Content-Length: {}\r\n".format(resource_size)
	headers += "Date: {}\r\n".format(datetime.datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT"))
	headers += "Server: {}\r\n".format(SERVER_NAME)
	headers += "Connection: keep-alive\r\n"
	headers += "Keep-Alive: timeout={}, max={}\r\n".format(TIMEOUT_CONNECTION, MAX_ACCESOS_TOTAL)
	# Si se ha recibido un valor de cookie, se añade la cabecera Set-Cookie.
	if cookie_value is not None:
		headers += "Set-Cookie: {}={}; Max-Age={}\r\n".format(COOKIE_CONTROL_ACCESOS, cookie_value, MAX_AGE)
	return headers


def send_error(cs: socket.socket, status_code: int, webroot: str):
	try: 
		# Construimos la respuesta de error y la enviamos.
		error_line = build_response_line(status_code)
		error_file = webroot + str(status_code) + ".html"
		error_headers = build_response_headers("text/html", get_resource_size(error_file), None)
		# Al ser ficheros pequeños, para tratar errores asumiremos que no fallará la lectura.
		error_body = open(error_file, "rb").read()
		error = error_line + error_headers + BODY_SEPARATOR
		encoded_error = encode(error)
		if encoded_error is not None:
			encoded_error += error_body
			send_data(cs, encoded_error)
		return
	except Exception as e:
		# Un error en envio de mensajes de error es catastrófico. Se debe cerrar la conexión.
		logger.error("[Addr {}] Error sending error response. {}".format(cs.getpeername(), e))
		raise Exception("Catasrophic error!")


def handle_get(path: str, cs: socket.socket, cookie_list, webroot: str):
	# Comprobamos si el recurso solicitado existe.
	if not os.path.exists(path):
		logger.debug("[Addr {}] Resource not found. 404 Not Found.".format(cs.getpeername()))
		send_error(cs, 404, webroot)
		return

	# Analizar permisos del recurso solicitado.
	if not os.access(path, os.R_OK):
		logger.debug("[Addr {}] Resource not accessible. 403 Forbidden.".format(cs.getpeername()))
		send_error(cs, 403, webroot)
		return

	# Procesamos las cookies si estamos accediendo al recurso index.html. Por defecto valdrá 0.
	cookie_counter = NO_COOKIE
	if path.endswith(LANDING_PAGE):
		cookie_counter = check_cookies(cookie_list, cs)
		# Si se ha llegado a MAX_ACCESOS devolver error de demasiados accesos al recurso principal.		
		if cookie_counter is MAX_ACCESOS_LANDING:
			logger.debug("[Addr {}] Max accesos reached. 429 Too Many Requests.".format(cs.getpeername()))
			send_error(cs, 429, webroot)
			return

	# Obtenemos el tipo de recurso solicitado.
	resource_type = get_resource_type(path)
	if resource_type is None:
		logger.debug("[Addr {}] Error getting resource type. 415 Unsupported Media Type.".format(cs.getpeername()))
		send_error(cs, 415, webroot)
		return

	# Obtenemos el tamaño del recurso solicitado.
	resource_size = get_resource_size(path)
	# Empezamos a construir la respuesta.
	response = build_response_line(200)
	response += build_response_headers(resource_type, resource_size, cookie_counter)
	response += BODY_SEPARATOR

	# Codificamos la respuesta en bytes.
	response_bytes  = encode(response)
	if response_bytes is None:
		logger.debug("[Addr {}] Error encoding response. 500 Internal Server Error.".format(cs.getpeername()))
		send_error(cs, 500, webroot)
		return
	
	# Añadimos y enviamos el contenido del recurso por lotes de BUFSIZE bytes.
	try:
		cur_size = len(response_bytes)
		with open(path, 'rb') as f:
			while True:
				chunk = f.read(BUFSIZE - cur_size)
				if not chunk:
					break
				response_bytes += chunk
				cur_size = len(response_bytes)
				sended = send_data(cs, response_bytes)
				response_bytes = response_bytes[sended:]
				cur_size -= sended

	except IOError or OSError as err:
		logger.debug("[Addr {}] Error sending or reading the resource: {}. 500 Internal Server Error.".format(cs.getpeername(), err))
		send_error(cs, 500, webroot)
		return
	
	logger.debug("[Addr {}] Resource sent successfully.".format(cs.getpeername()))
	return


def handle_post(path: str, body: str, cs: socket.socket, cookie_list, webroot: str):
	
	# Comprobar si el cuerpo es el correo electrónico correcto.
	if not body == ADMIN_EMAIL:
		logger.debug("[Addr {}] Wrong email. 401 Unauthorized.".format(cs.getpeername()))
		send_error(cs, 401, webroot)
		return
	
	# Por la simplicidad del escenario, podemos hacer una llamada al método GET para enviar el recurso pedido ya que 
	# el comportamiento es el mismo. Se debe devolver el recsurso ya que el email es válido.
	handle_get(path, cs, cookie_list, webroot)
	return


def process_web_request(cs: socket.socket, webroot: str) -> int:
	logger.debug("[Addr {}] Processing web request...".format(cs.getpeername()))
	# Creamos un selector y registramos el socket para lectura.
	try:
		sel = selectors.DefaultSelector()
		sel.register(cs, selectors.EVENT_READ)
	except ValueError or KeyError or OSError as err:
		logger.error("Error registering {} socket on a selector: {}\nAborting...".format(cs.getpeername(), err))
		return ERROR
	
	try:
		# Contador de peticiones totales de la conexión.
		contador_accesos = 0
		# Bucle para esperar hasta que lleguen datos en la red a través del socket cs con select()
		while True:
			
			# Control de accessos totales.
			if contador_accesos >= MAX_ACCESOS_TOTAL:
				logger.debug("[Addr {}] Max accesos reached. 429 Too Many Requests.".format(cs.getpeername()))
				send_error(cs, 429, webroot)
				sel.close()
				return SUCCESS
			
			# Se comprueba si el coket registrado dispone de datos para leer. Se usa timeout para cerrar la conexión si no se reciben datos en ese tiempo.
			events = sel.select(timeout=TIMEOUT_CONNECTION)
			
			# Si no hay eventos, se cierra la conexión por timeout.
			if not events:
				logger.debug("[Addr {}] Timeout!. 408 Request Timeout.".format(cs.getpeername()))
				send_error(cs, 408, webroot)
				sel.close()
				return SUCCESS
			
			# Incrementamos el contador de accesos.
			contador_accesos += 1

			# Como el socket se ha registrado solo para lectura, si hay eventos es porque hay datos para leer.
			# Se asume de aqui en adelante que cualquier petición cabe en un buffer de BUFFER_SIZE bytes y no habrán varias peticiones en un mismo buffer.
			try:
				data = recv_data(cs)
				logger.debug("[Addr {}] Received {} bytes.".format(cs.getpeername(), len(data)))
			except OSError as err:
				logger.error("Error receiving data from {} socket: {}\nIgnoring request...".format(cs.getpeername(), err))
				continue

			# Decoficamos los datos recibidos.
			data = decode(data)
			if data is None:
				logger.debug("[Addr {}] Error decoding data. 400 Bad Request.".format(cs.getpeername()))
				send_error(cs, 400, webroot)
				continue

			# Parseamos los datos y extraemos los campos de los datos.
			data = parse_data(data)
			request = data[0]
			headers = data[1]
			body = data[2]

			# Se comprueba la línea de petición.
			request = parse_request(request)
			if request is None:
				logger.debug("[Addr {}] Error parsing request. 400 Bad Request.".format(cs.getpeername())) 
				send_error(cs, 400, webroot)
				continue

			# Extraemos los campos de la petición.
			method = request[0]
			path = request[1]
			version = request[2]
			logger.debug("[Addr {}] Request line: {} {} {}".format(cs.getpeername(), method, path, version))

			# Comprobamos la versión HTTP para ver si es adecuada.
			if version != HTTP_VERSION:
				logger.debug("[Addr {}] Mismatched HTTP version on request. 505 HTTP Version Not Supported.".format(cs.getpeername()))
				send_error(cs, 505, webroot)
				continue

			# Procesamos las cabeceras.
			headers = parse_headers(headers)
			if headers is None:
				logger.debug("[Addr {}] Error parsing headers. 400 Bad Request.".format(cs.getpeername()))
				send_error(cs, 400, webroot)
				continue

			# Extraemos los campos de las cabeceras.
			header_dict = headers[0]
			cookie_list = headers[1]

			# Construirimos la ruta al recurso.
			path = build_absolute_path(webroot, path)
			logger.debug("[Addr {}] Resource requested: {}".format(cs.getpeername(), path))
			
			# Según el método lo procesamos.
			if method == "GET":	
				# Comprobamos si la petición incluye la cabecera Host.
				if not check_headers(header_dict, cs):
					logger.debug("[Addr {}] Host header not found. 400 Bad Request.".format(cs.getpeername()))
					send_error(cs, 400, webroot)
					continue
				handle_get(path, cs, cookie_list, webroot)
			elif method == "POST":
				# Comprobamos si la petición incluye la cabecera Host.
				if not check_headers(header_dict, cs):
					logger.debug("[Addr {}] Host header not found. 400 Bad Request.".format(cs.getpeername()))
					send_error(cs, 400, webroot)
					continue
				handle_post(path, body, cs, cookie_list, webroot)
			else:
				logger.debug("[Addr {}] Method requested not valid. 405 Method Not Allowed.".format(cs.getpeername()))
				send_error(cs, 405, webroot)

	except Exception as err:
		# Aqui solo se llega por errores catastróficos.
		logger.error("Error processing web request: {}\nAborting...".format(err))
		return ERROR


def main():
	try:
		# Argument parser para obtener la ip y puerto de los parámetros de ejecución del programa.
		parser = argparse.ArgumentParser()
		parser.add_argument("-p", "--port", help="Puerto del servidor", type=int, required=True)
		parser.add_argument("-ip", "--host", help="Dirección IP del servidor o localhost", required=True)
		parser.add_argument("-wb", "--webroot", help="Directorio base desde donde se sirven los ficheros (p.ej. /home/user/mi_web)", required=True)
		parser.add_argument('--verbose', '-v', action='store_true', help='Incluir mensajes de depuración en la salida')
		args = parser.parse_args()

		# Si se ha indicado modo verboso se activa el nivel de logging DEBUG.
		if args.verbose:
			logger.setLevel(logging.DEBUG)

		logger.info('Enabling server in address {} and port {}.'.format(args.host, args.port))
		logger.info("Serving files from {}".format(args.webroot))

		# Creamos un socket TCP, permitiendo reusar la misma dirección previamente vinculada a otro proceso.
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=0)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		except OSError as err:
			logger.error("Socket creation error: {}\nAborting execution...".format(err))
			sys.exit(ERROR)

		# Vinculamos el socket a una IP y puerto elegidos y escuchamos conexiones entrantes.
		try:
			sock.bind((args.host, args.port))
			sock.listen()
		except OSError as err:
			cerrar_conexion(sock)
			logger.error("Socket binding error: {}\nAborting execution...".format(err))
			sys.exit(ERROR)
		
		# Bucle infinito para mantener el servidor activo indefinidamente
		while True:

			# Aceptamos la conexión entrante y creamos un socket para gestionarla.
			try:
				cs, addr = sock.accept()
			except OSError as err:
				logger.error("Error accepting connection: {}".format(err))
				continue

			logger.info("Connection accepted from {}".format(addr))

			# Creamos un proceso hijo para gestionar la conexión entrante.
			try:
				pid = os.fork()
			except OSError as err:
				logger.error("Error creating child process: {}".format(err))
				continue

			# Cerramos el socket del padre y procesamos la petición con el hijo.
			if pid == 0:
				cerrar_conexion(sock)
				status = process_web_request(cs, args.webroot)
				cerrar_conexion(cs)
				logger.info("Connection with {} closed.".format(addr))
				sys.exit(status)

			# Cerramos el socket del hijo.
			cerrar_conexion(cs)

	except KeyboardInterrupt:
		logger.info("Server manually stopped by admin.")
		sys.exit(SUCCESS)

	except OSError as err:
		logger.error("Unexpected error: {}\nAborting execution...".format(err))
		sys.exit(ERROR)


if __name__== "__main__":
	main()