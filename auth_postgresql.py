import psycopg2
import psycopg2.extras
import os
import jwt
import logging
import struct
import sys


def passwd_file(file_env_name, env_name, default='PlsChgMe!'):
    """
    Get content of file path if exists or environment value or default value

    :param file_env_name: Environment var name with path of password file
    :param pass_env_name: Environment var name with password
    :default pass_env_name: Default value

    :returns: String conten of file or env or default
    """
    file_name = os.environ.get(file_env_name, None)
    if file_name:
        if os.path.exists(file_name) and os.access(file_name, os.R_OK):
            with open(file_name, 'r') as file_open:
                return file_open.read()
    return os.environ.get(env_name, default)

#change this to your secret key
SECRET_KEY = passwd_file(
    'SECRET_KEY_FILE', 'SECRET_KEY',
    'secret_key')
HOST = os.environ.get('HOST', 'localhost')
DATABASE = os.environ.get('DATABASE', 'ejabberd')
USER = os.environ.get('DATABASE_USER', 'ejabberd_user')
PASSWORD = os.environ.get('PASSWORD', 'password')

# sys.stdin.reconfigure(encoding="latin_1")
exitcode = 0

try:
    database = psycopg2.connect(
        host=HOST,
        database=DATABASE,
        user=USER,
        password=PASSWORD
    )
    logging.info('Connected to database')
except Exception as e:
    logging.error(f"Could not connect to database: {e}")
    sys.exit(1)


class EjabberdInputError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


def from_ejabberd():
    logging.debug("trying to read 2 bytes from ejabberd:")

    input_length = sys.stdin.buffer.read(2)
    # (size,) = struct.unpack(bytes('>h', 'latin_1'), bytes(input_length, 'latin_1'))

    #(size,) = struct.unpack(bytes('>h', 'UTF-8'), bytes(input_length, 'UTF-8'))
    (size,) = struct.unpack('>h', input_length)
    logging.debug(f"size: {size}")
    return sys.stdin.read(size).split(':')


def to_ejabberd(bool):
    answer = 0
    if bool:
        answer = 1
    token = struct.pack('>hh', 2, answer)
    sys.stdout.buffer.write(token)
    sys.stdout.buffer.flush()
    sys.stdout.flush()


def decode_token(token):
    """
    format of the payload:
    {
        'username', 
        'exp',
        'iat'
    }
    """
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return decoded
    except Exception as e:
        logging.error(f"Could not decode token: {e}")
        return None


def auth(username, server, password):
    logging.error(f"NOMBRE DE USUARIO Y CONTRASENA: {username}\n{password}")
    decoded = decode_token(password)
    cursor = database.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute(
        "SELECT * FROM users WHERE username = %s",
        (username,)
    )
    result = cursor.fetchone()
    if result:
        if decoded:
            if username == decoded['username']:
                logging.info(f"User {username} authenticated")
                return True
        if result['password'] == password:
            logging.info(f"User {username} authenticated")
            return True
    return False


def isuser(username, server):
    cursor = database.cursor()
    cursor.execute(
        "SELECT username FROM users WHERE username = %s",
        (username,)
    )
    result = cursor.fetchone()
    if result is None:
        return False
    return True


while True:
    logging.debug("start of infinite loop")

    try:
        ejab_request = from_ejabberd()
    except EOFError:
        break
    except Exception as e:
        logging.exception("Exception occured while reading stdin")
        raise

    logging.debug(f"operation: {':'.join(ejab_request)}")

    op_result = False
    # logging.debug(f"{ejab_request[0]}")
    try:
        if ejab_request[0] == "auth":
            op_result = auth(ejab_request[1], ejab_request[2], ejab_request[3])
        elif ejab_request[0] == "isuser":
            op_result = isuser(ejab_request[1], ejab_request[2])
    except Exception:
        logging.exception("Exception occured")
    to_ejabberd(op_result)
    logging.debug("successful" if op_result else "unsuccessful")

logging.debug("end of infinite loop")
logging.info('extauth script terminating')
database.close()
sys.exit(exitcode)
