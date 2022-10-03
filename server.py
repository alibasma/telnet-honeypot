import socket
import sys
import threading
import logging


logging.basicConfig(filename="monhoneypot.log",format='%(asctime)s %(message)s',filemode='a+') #creation and configuration for the log file

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

HEADER = 64
PORT = 5050   #port 5050 is use here for the honeypot

SERVER = socket.gethostbyname(socket.gethostname()) #we get the ip address of the server
ADDR = ('', PORT)
FORMAT= 'utf-8'

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setblocking(1)
server.bind(ADDR)



def handle_client(conn, addr) :
    while True :
        repertoire = "root@34.125.83.147:~#" #change the ip address displayed, and put the one that belongs to you
        passwordtrouver = True

        data = conn.recv(64)
        print(data)
        if not data:
            break

        Dossiercreer = []
        dernierdossier=""
        afficherdossier = 0
        conn.send("Ubuntu 20.04.5 LTS\n\r".encode('utf8'))

        while passwordtrouver: #here we manage the authentication

            conn.send("login:".encode('utf8'))
            login = conn.recv(64)

            if login.decode('utf8') == '':
                sys.exit()

            logger.debug(str(addr) + " " + "login: " + " " + login.decode('utf8'))
            conn.send("Password:".encode('utf8'))
            password = conn.recv(64)
            if password.decode('utf8') == '':
                sys.exit()
            logger.debug(str(addr) + " " + "mot de passe : " + " "  + password.decode('utf8'))
            if "passer".encode('utf-8') in password and "root".encode('utf-8') in login:
                print(password)
                passwordtrouver= False
            else :
                conn.send("\n\rLogin incorrect\n\r".encode('utf8'))

        while True: #if the authentication is successful this is where we will process the orders
            conn.send(repertoire.encode('utf8'))
            cmd = conn.recv(64)
            cmddecode=cmd.decode('utf8')
            print(cmd.decode('utf8'))
            logger.debug(str(addr) + " " + "commande taper: " +" "+ cmd.decode('utf8'))

            if repertoire == "root@34.125.83.147:~#": #change the ip address displayed, and put the one that belongs to you
                if "ls" == cmd.decode('utf8').strip('\n\r') :
                    for dir in Dossiercreer :
                        if afficherdossier == 4 :
                            conn.send(b"\n\r")
                        else :
                            afficherdossier=+1
                            conn.send(bytes(dir+ "         ", encoding='utf-8'))

                        if dir == dernierdossier :
                            conn.send(b"\n\r")

                elif "pwd" == cmd.decode('utf8').strip('\n\r'):
                    conn.send(b"/root\n\r")
                elif "cd .." == cmd.decode('utf8').strip('\n\r'):
                    repertoire = "root@34.125.83.147:/#" #change the ip address displayed, and put the one that belongs to you
                elif "mkdir".encode('utf-8') in cmd:
                    cmdsplist = cmd.decode('utf8').split()
                    filename = cmdsplist[1]
                    Dossiercreer.append(filename)
                    dernierdossier = cmdsplist[1]
                elif "wget".encode('utf-8') in cmd or "rm -rf".encode('utf-8') in cmd or "rm".encode('utf-8') in cmd or "top".encode('utf-8') in cmd or "ps -aux".encode('utf-8') in cmd:
                    conn.send(b"\n\r")

                elif cmd.decode('utf8') == '':
                    sys.exit()
                else:
                    nocmd = bytes(cmd.decode('utf8').strip('\n\r') + ": command not found\n\r", encoding='utf-8')
                    conn.send(nocmd)


            elif repertoire == "root@34.125.83.147:/#": #change the ip address displayed, and put the one that belongs to you
                if "ls" == cmd.decode('utf8').strip('\n\r'):
                    conn.send(b"bin   dev  home  lib32  libx32      media  opt   root  sbin  srv  tmp  var\n\rboot  etc  lib   lib64  lost+found  mnt    proc  run   snap  sys  usr\n\r")

                elif "cd root" == cmd.decode('utf8').strip('\n\r'):
                    repertoire = "root@34.125.83.147:~#"
                elif "pwd" == cmd.decode('utf8').strip('\n\r') :
                    conn.send(b"/\n\r")
                elif cmd.decode('utf8') == '':
                    sys.exit()
                elif "wget".encode('utf-8') in cmd or "rm -rf".encode('utf-8') in cmd or "rm".encode('utf-8') in cmd or "top".encode('utf-8') in cmd or "ps -aux".encode('utf-8') in cmd in cmd:
                    conn.send(b"\n\r")
                else:
                    nocmd = bytes(cmd.decode('utf8').strip('\n\r') + ": command not found\n\r",encoding='utf-8')
                    conn.send(nocmd)




def start():
    server.listen()
    print("Le serveur ecoute sur "+ SERVER + " port 5050")

    while True :
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        connexionencours = f"Nouvelle connection {addr} connecter"
        print(connexionencours)
        logger.debug(connexionencours)

print("Le honeypot telnet est lancée...")

start()





