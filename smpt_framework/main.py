import socket
import threading
import base64

"""
[INIT]
EHLO <domain>
Port 2525 - Response: 250-e25dbb8f4dc7
250-SIZE 33554432
250-8BITMIME
250-SMTPUTF8
250 HELP

HELO 250-e25dbb8f4dc7

RESP -> Port 2525 - Response: 250 Hello, pleased to meet you!


[SENDING]
MAIL FROM admin@250-e25dbb8f4dc7 -> RES: OK 

"""

# Функция для отображения справки с командами SMTP
def print_help():
    help_text = """
    === Welcome to the CyberMail Protocol Tester ===

    Available commands for both ports:

    - EHLO <domain>       : Initiates a connection and identifies the client. (Use 'EHLO example.com' to test)
    - HELO <domain>       : Same as EHLO, but less commonly used.
    - AUTH <mechanism>    : Starts authentication with a specified mechanism (e.g., 'AUTH LOGIN').
    - MAIL FROM <address>  : Specifies the sender's email address (e.g., 'MAIL FROM:<test@example.com>').
    - RCPT TO <address>   : Specifies the recipient's email address (e.g., 'RCPT TO:<recipient@example.com>').
    - DATA                : Initiates sending message data.
    - VRFY <user>         : Verifies if a user exists on the server. (e.g., 'VRFY admin')
    - NOOP                : No-op command, does nothing, used for testing.
    - RSET                : Resets the session (clears the current state).
    - QUIT                : Closes the connection to the server.
    - HELP                : Shows this help message.
    - EXIT                : Exits the current connection to the server.

    Format:
    - Commands should be followed by <CRLF> (i.e., "\r\n").

    Note: Commands are case-insensitive, but be sure to use the correct syntax for each command.

    =====================================================
    """
    print(help_text)

# Подключение и взаимодействие с сервером на порту 2526
def connect_to_port_2526(host):
    try:
        print(f"Connecting to {host}:2526...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)  # Устанавливаем тайм-аут для подключения
            s.connect((host, 2526))  # Подключаемся к хосту на порту 2526

            # Получаем и выводим баннер сервера
            banner = s.recv(4096).decode()
            print(f"\nPort 2526 - Banner: {banner.strip()}")

            while True:
                # Пользователь вводит команду
                user_command = input("Enter a command for port 2526 (or 'exit' to quit)\n> ").strip()
                if user_command.lower() == 'exit':  # Команда выхода
                    print("Exiting port 2526...")
                    break

                # Отправляем команду на сервер
                user_command = user_command + "\r\n"
                print(f"Sending to port 2526: {user_command.strip()}")
                s.sendall(user_command.encode())
                
                # Получаем ответ от сервера
                response = s.recv(4096).decode()
                print(f"Port 2526 - Response: {response.strip()}")
                
                # Пытаемся декодировать ответ, если он закодирован в Base64
                if "base64" in response.lower():
                    try:
                        decoded_response = base64.b64decode(response.strip())
                        print(f"Decoded response: {decoded_response.decode()}")
                    except Exception as e:
                        print(f"Failed to decode base64 response: {e}")

    except Exception as e:
        print(f"Error with port 2526: {e}")

# Подключение и взаимодействие с сервером на порту 2525
def connect_to_port_2525(host):
    try:
        print(f"\nConnecting to {host}:2525...\n")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)  # Тайм-аут
            s.connect((host, 2525))  # Подключаемся к хосту на порту 2525

            # Получаем баннер сервера
            banner = s.recv(4096).decode()
            print(f"\nPort 2525 - Banner: {banner.strip()}\n")

            # Отправляем команду EHLO для тестирования соединения
            helo_command = "EHLO example.com\r\n"
            print(f"\nSending to port 2525: {helo_command.strip()}\n")
            s.sendall(helo_command.encode())
            response = s.recv(4096).decode()
            print(f"\nPort 2525 - Response: {response.strip()}\n")

            while True:
                # Ввод команды пользователем
                user_command = input("\nEnter a command for port 2525 (or 'exit' to quit)\n>").strip()
                if user_command.lower() == 'exit':  # Команда выхода
                    print("Exiting port 2525...")
                    break

                # Отправляем команду и обрабатываем ответ
                user_command = user_command + "\r\n"
                print(f"Sending to port 2525: {user_command.strip()}")
                s.sendall(user_command.encode())
                response = s.recv(4096).decode()
                print(f"Port 2525 - Response: {response.strip()}")

                # Если началась аутентификация, вызываем обработчик
                if user_command.upper().startswith("AUTH LOGIN"):
                    handle_auth_login(s)

                # Проверяем на необычные ответы
                if "error" in response.lower() or "unknown" in response.lower():
                    print(f"Unusual response: {response.strip()}")

                # Декодируем Base64-ответы, если возможно
                if "base64" in response.lower():
                    try:
                        decoded_response = base64.b64decode(response.strip())
                        print(f"Decoded response: {decoded_response.decode()}")
                    except Exception as e:
                        print(f"Failed to decode base64 response: {e}")

    except Exception as e:
        print(f"Error with port 2525: {e}")

# Обработка команды AUTH LOGIN
def handle_auth_login(s):
    print("Starting AUTH LOGIN procedure...")

    # Отправляем команду AUTH LOGIN
    s.sendall(b"AUTH LOGIN\r\n")
    response = s.recv(4096).decode()
    print(f"Response: {response.strip()}")

    # Ввод логина
    login = input("Enter your login (Base64 encoded): ").strip()
    s.sendall(base64.b64encode(login.encode()) + b"\r\n")
    response = s.recv(4096).decode()
    print(f"Response: {response.strip()}")

    # Ввод пароля
    password = input("Enter your password (Base64 encoded): ").strip()
    s.sendall(base64.b64encode(password.encode()) + b"\r\n")
    response = s.recv(4096).decode()
    print(f"Response: {response.strip()}")

# Основная функция
def main():
    host = "83.149.213.4"  # IP-адрес сервера

    print_help()  # Показываем справку с командами

    # Создаем два потока для подключения к портам 2525 и 2526
    thread_2526 = threading.Thread(target=connect_to_port_2526, args=(host,))
    thread_2525 = threading.Thread(target=connect_to_port_2525, args=(host,))

    thread_2526.start()
    thread_2525.start()

    thread_2526.join()
    thread_2525.join()

# Точка входа
if __name__ == "__main__":
    main()