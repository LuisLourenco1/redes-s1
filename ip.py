from iputils import *
import struct
import ipaddress


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        
        self.tabela = None

    ''' Passo 4 '''
    # Função auxiliar para montar o cabeçalho IP
    def montar_cabecalho(self, total_len, ttl, proto, src_addr, dst_addr):
        src_addr = ipaddress.IPv4Address(src_addr) # Endereço de origem
        dst_addr = ipaddress.IPv4Address(dst_addr) # Endereço de destino
        
        cabecalho = struct.pack('!BBHHHBBHII',
                        (4 << 4) + 5, (0 << 2) + 0, total_len, 0, (0 << 13) + 0,
                        ttl, proto, 0, int(src_addr), int(dst_addr))
        
        checksum = calc_checksum(cabecalho)
        
        cabecalho = struct.pack('!BBHHHBBHII',
                        (4 << 4) + 5, (0 << 2) + 0, total_len, 0, (0 << 13) + 0,
                        ttl, proto, checksum, int(src_addr), int(dst_addr))
        
        return cabecalho

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            
            ''' Passo 4 '''
            
            # Decrementa o TTL
            ttl = ttl-1
            
            ''' Passo 5 '''
            # Se o TTL for 0, o datagrama é descartado
            # E é gerada uma mensagem do tipo ICMP Time exceeded que é enviada de volta ao remetente
            if ttl == 0:
                # Atualiza o next_hop para o endereço de origem do datagrama
                next_hop = self._next_hop(src_addr)
                
                # Montando o cabeçalho IP com os endereços invertidos e com o protocolo ICMP (IPPROTO_ICMP = 1)
                cabecalho_ip = self.montar_cabecalho(48, 64, IPPROTO_ICMP, self.meu_endereco, src_addr)
                
                # Atributos do cabeçalho ICMP (4 atributos)
                # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header
                
                type = 11 # Time exceeded
                code = 0
                checksum = 0 # Será calculado depois de montar o cabeçalho
                unused = 0
                rest = datagrama[:28] # 28 bytes do datagrama original
                
                # Montando o cabeçalho ICMP para calcular o checksum
                cabecalho_icmp = struct.pack('!BBHHH',
                                type, code, checksum, unused, 0)
                
                checksum = calc_checksum(cabecalho_icmp + cabecalho_ip)
                
                # Montando o cabeçalho ICMP com o checksum correto
                cabecalho_icmp = struct.pack('!BBHHH',
                                type, code, checksum, unused, 0)
                
                self.enlace.enviar(cabecalho_ip + cabecalho_icmp + rest, next_hop)
                
                return
    
            # Monta o cabeçalho IP com o TTL decrementado
            cabecalho = self.montar_cabecalho(20 + len(datagrama), ttl, 6, src_addr, dst_addr)
            
            # Monta o datagrama com o cabeçalho IP e o payload
            datagrama = cabecalho + payload
            
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        
        ''' Passo 1 '''
        dest = ipaddress.ip_address(dest_addr)
        
        l = [] # Lista para desempate
        
        for cidr, next_hop in self.tabela:
            c = ipaddress.ip_network(cidr)
            
            ''' Passo 3 '''
            if dest in c:
                l.append((c.prefixlen, next_hop))
        
        # Escolhe o next_hop com o maior prefixo
        if len(l) > 0:
            return max(l)[1]
            

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        
        ''' Passo 2 '''
        
        # Atributos do cabeçalho IP (13 atributos)
        # https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Header
        
        version = 4 # IPv4
        ihl = 5 # 5 palavras de 32 bits
        dscp = 0
        ecn = 0 
        total_len = 20 + len(segmento) # Tamanho total do datagrama
        identification = 0
        flags = 0
        frag_offset = 0
        ttl = 64
        proto = 6
        checksum = 0 # Será calculado depois de montar o cabeçalho
        
        src_addr = ipaddress.IPv4Address(self.meu_endereco) # Endereço de origem
        dst_addr = ipaddress.IPv4Address(dest_addr) # Endereço de destino
        
        # Montando o cabeçalho IP para calcular o checksum
        cabecalho = struct.pack('!BBHHHBBHII',
                        (version << 4) + ihl, (dscp << 2) + ecn, total_len, identification, (flags << 13) + frag_offset,
                        ttl, proto, checksum, int(src_addr), int(dst_addr))
        
        checksum = calc_checksum(cabecalho)
        
        # Montando o cabeçalho IP com o checksum correto
        cabecalho = struct.pack('!BBHHHBBHII',
                        (version << 4) + ihl, (dscp << 2) + ecn, total_len, identification, (flags << 13) + frag_offset,
                        ttl, proto, checksum, int(src_addr), int(dst_addr))
        
        # Monta o datagrama (cabecalho antes do segmento)
        datagrama = cabecalho + segmento 
        
        self.enlace.enviar(datagrama, next_hop)
