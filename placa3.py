#!/usr/bin/env python3
import asyncio
from camadafisica import ZyboSerialDriver
from tcp import Servidor        # copie o arquivo do T2
from ip import IP               # copie o arquivo do T3
from slip import CamadaEnlace   # copie o arquivo do T4

import re

## Implementação da camada de aplicação

def validar_nome(nome):
    return re.match(br'^[a-zA-Z][a-zA-Z0-9_-]*$', nome) is not None

def sair(conexao):
    print(conexao, 'conexão fechada')
    
    # Itera pelos canais em que o usuário está
    if hasattr(conexao, 'canais'):
        for nome_canal in conexao.canais:
            if conexao in canais[nome_canal.lower()]:
                canais[nome_canal.lower()].remove(conexao) # Remove o usuário da lista de nomes do canal
            
            for user in canais[nome_canal.lower()]: # Itera pelos usuários de cada canal em que o usuário está
                user.enviar(b':%s QUIT :Connection closed\r\n' % conexao.nick)
            
    # Remove o nome do usuário da lista de apelidos
    if conexao.nick.lower() != b'':
        del apelidos[conexao.nick.lower()]

    conexao.fechar()

def getComando(string, comando):
    return string.startswith(comando)

def dados_recebidos(conexao, dados):
    if dados == b'':
        return sair(conexao)
    
    # Separa os comandos (b'\r\n') sem apagar os b'\r\n'
    pattern = b'(?<=\r\n)'
    dados = [substring for substring in re.split(pattern, dados)]
    
    
    for d in dados: # Itera sob cada comando
        if d.endswith(b'\r\n'): # Processa os comandos bem formados
            d = conexao.residuais + d # Concatena os residuais com os dados
            
            
            # Comando PING
            if getComando(d, b'PING'):
                d = d.replace(b'PING ', b'')
                conexao.enviar(b':server PONG server :' + d)


            # Comando NICK
            if getComando(d, b'NICK'):
                nick = d.replace(b'NICK ', b'').replace(b'\r\n', b'')
                
                # Caso 1: Nome válido
                if validar_nome(nick):
                    
                    # Caso 1.1: Nick NÃO-disponível (não Case-Sensitive)
                    if nick.lower() in apelidos:
                        
                        # Caso 1.1.1: 1o acesso
                        if conexao.nick == b'':
                            conexao.enviar(b':server 433 * %s :Nickname is already in use\r\n' % nick)
                            
                        # Caso 1.1.2: Troca
                        else:
                            conexao.enviar(b':server 433 %s %s :Nickname is already in use\r\n' % (conexao.nick, nick))
                    
                    # Caso 1.2: Nick disponível    
                    else:
                        # Caso 1.2.1: 1o acesso
                        if conexao.nick == b'':
                            conexao.enviar(b':server 001 %s :Welcome\r\n' % nick)
                            conexao.enviar(b':server 422 %s :MOTD File is missing\r\n' % nick)
                            
                        # Caso 1.2.2: Troca
                        else:
                            conexao.enviar(b':%s NICK %s\r\n' % (conexao.nick, nick))
                            del apelidos[conexao.nick.lower()] # Apaga o nome antigo do dicionário
                            # Se não apagar, durante o 'if valor in apelidos.values()' pode achar a conexão antiga
                            
                        # Registra independente do caso
                        apelidos[nick.lower()] = conexao # Associa o nome e a conexão
                        conexao.nick = nick # Registra o nome da conexão no objeto

                # Caso 2: Nome inválido
                else:
                    conexao.enviar(b':server 432 * %s :Erroneous nickname\r\n' % nick)
                    
                    
            # Comando PRIVMSG
            if getComando(d, b'PRIVMSG'):
                priv = d.replace(b'PRIVMSG ', b'').replace(b'\r\n', b'')
                dest, msg = priv.split(b' :', 1)
                
                # Caso 1: Usuário
                if dest.lower() in apelidos:
                    apelidos[dest.lower()].enviar(b':%s PRIVMSG %s :%s\r\n' % (conexao.nick, dest, msg))
                
                # Caso 2: Canal
                if dest.startswith(b'#'):
                    nome_canal = dest.replace(b'#', b'')
                    
                    # Verifica se o usuário está no canal
                    if conexao in canais[nome_canal.lower()]:
                        # Manda para todos os usuários que estão naquela canal
                        for user in canais[nome_canal.lower()]:
                            if user != conexao:
                                user.enviar(b':%s PRIVMSG %s :%s\r\n' % (conexao.nick, b'#' + nome_canal, msg))

     
            # Comando JOIN
            if getComando(d, b'JOIN'):
                nome_canal = d.replace(b'JOIN ', b'').replace(b'\r\n', b'')
                
                # Caso 1: Nome do canal válido
                if validar_nome(nome_canal.replace(b'#', b'')) and nome_canal.startswith(b'#'):
                    nome_canal = nome_canal.replace(b'#', b'')
                    
                    # Canal não existe ainda     
                    if nome_canal.lower() not in canais:
                        canais[nome_canal.lower()] = [] # Cria a lista de nomes
                    
                    # Usuário não está no canal ainda
                    if conexao not in canais[nome_canal.lower()]:
                        canais[nome_canal.lower()].append(conexao) # Registra a conexão do usuário no canal
                        
                        # Envia a mensagem de JOIN para todos os usuários do canal
                        for user in canais[nome_canal.lower()]:
                            user.enviar(b':%s JOIN :%s\r\n' % (conexao.nick, b'#' + nome_canal))
                    
                    # Registra o canal na lista de canais da conexão
                    if nome_canal.lower() not in conexao.canais:
                        conexao.canais.append(nome_canal.lower())
                        
                    # Passo 8
                    lista_nomes = [user.nick for user in canais[nome_canal.lower()]]
                    lista_nomes = b' '.join(sorted(lista_nomes))
                    
                    # Envia a lista e o fim da lista para o novo membro do canal
                    conexao.enviar(b':server 353 %s = %s :%s\r\n' % (conexao.nick, b'#' + nome_canal, lista_nomes))
                    conexao.enviar(b':server 366 %s %s :End of /NAMES list.\r\n' % (conexao.nick, b'#' + nome_canal))
                
                # Caso 2: Nome do canal inválido
                else:
                    conexao.enviar(b':server 403 canal :No such channel\r\n')
                    
            
            # Comando PART
            if getComando(d, b'PART'):
                # Remove tudo, inclusive a mensagem de partida, deixando apenas o nome do canal
                nome_canal = d.replace(b'PART ', b'').replace(b'\r\n', b'').split(b' :', 1)[0]
                
                # Se o canal começa com #
                if nome_canal.startswith(b'#'):
                    nome_canal = nome_canal.replace(b'#', b'')
                    
                    # Se o canal existe, se o usuário está no canal
                    if nome_canal.lower() in canais and nome_canal.lower() in conexao.canais:
                        
                        # Envia para todos os usuários do canal
                        for user in canais[nome_canal.lower()]:
                            user.enviar(b':%s PART %s\r\n' % (conexao.nick, b'#' + nome_canal))
                            
                        # Remove a conexão do canal e o canal da lista da conexão
                        canais[nome_canal.lower()].remove(conexao)
                        conexao.canais.remove(nome_canal.lower())
        
        
                
            # Printa
            print(conexao, d)
            
            # Reseta o resíduo
            conexao.residuais = b''
            
        else:
            # Concatena os dados que não terminam com b'\n' e salva nos residuais
            conexao.residuais += d

    # Caso os resíduos se completem e não hajam mais mensagens em seguida
    if conexao.residuais.endswith(b'\r\n'):
        conexao.enviar(b':server PONG server :' + conexao.residuais.replace(b'PING ', b'')) # Remove o comando PING
        conexao.residuais = b''
        
        print(conexao, d)



def conexao_aceita(conexao):
    # Passo 2
    conexao.residuais = b''
    
    # Passo 4
    conexao.nick = b''
    
    # Passo 5
    conexao.canais = []
    
    print(conexao, 'nova conexão')
    conexao.registrar_recebedor(dados_recebidos)
    

# Lista de nomes
apelidos = {}

# Lista de canais
canais = {}


## Integração com as demais camadas

nossa_ponta = '192.168.200.4'
outra_ponta = '192.168.200.3'
porta_tcp = 7000

driver = ZyboSerialDriver()
linha_serial = driver.obter_porta(0)

enlace = CamadaEnlace({outra_ponta: linha_serial})
rede = IP(enlace)
rede.definir_endereco_host(nossa_ponta)
rede.definir_tabela_encaminhamento([
    ('0.0.0.0/0', outra_ponta)
])
servidor = Servidor(rede, porta_tcp)
servidor.registrar_monitor_de_conexoes_aceitas(conexao_aceita)
asyncio.get_event_loop().run_forever()
