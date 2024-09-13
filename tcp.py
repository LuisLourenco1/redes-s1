import asyncio
import time
from tcputils import *
import random
import os

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return
        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no, seq_no + 1)
            header = make_header(dst_port, src_port, conexao.seq_no, conexao.seq_no_esperado, FLAGS_SYN | FLAGS_ACK)
            header = fix_checksum(header, dst_addr, src_addr)
            conexao.servidor.rede.enviar(header, src_addr)
            conexao.seq_no += 1
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
            if (flags & FLAGS_FIN) == FLAGS_FIN:
                conexao = self.conexoes[id_conexao]
                conexao.callback(conexao, b'')
                segmento = make_header(dst_port, src_port, conexao.seq_no, conexao.seq_no_esperado, FLAGS_FIN | FLAGS_ACK)
                segmento = fix_checksum(segmento, dst_addr, src_addr)
                conexao.servidor.rede.enviar(segmento, src_addr)
                del conexao.servidor.conexoes[conexao.id_conexao]
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' % (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.seq_no_esperado = ack_no
        self.seq_no = seq_no
        self.dados_total = []
        self.enviados = {}
        self.timer = None
        self.timeout_interval = 1  # valor inicial de exemplo
        self.estimated_rtt = None
        self.dev_rtt = None
        self.cwnd = MSS
        self.ssthresh = 64 * MSS

    def _iniciar_timer(self):
        if self.timer:
            self.timer.cancel()
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self._timeout)

    def _timeout(self):
        self.timeout_interval *= 2
        for segmento, endereco in self.enviados.values():
            self.servidor.rede.enviar(segmento, endereco)
        self._iniciar_timer()
        self.cwnd = max(MSS, self.cwnd // 2)

    def _atualizar_rtt(self, sample_rtt):
        if self.estimated_rtt is None:
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2
        else:
            self.estimated_rtt = 0.875 * self.estimated_rtt + 0.125 * sample_rtt
            self.dev_rtt = 0.75 * self.dev_rtt + 0.25 * abs(sample_rtt - self.estimated_rtt)
        self.timeout_interval = self.estimated_rtt + 4 * self.dev_rtt

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        if ack_no > self.seq_no:
            self.seq_no = ack_no
            if self.timer:
                self.timer.cancel()
                self.timer = None
            if self.seq_no in self.enviados:
                sample_rtt = time.time() - self.enviados[self.seq_no][2]
                self._atualizar_rtt(sample_rtt)
                del self.enviados[self.seq_no]
            self.cwnd = min(self.cwnd + MSS, self.ssthresh) if self.cwnd < self.ssthresh else self.cwnd + MSS * (MSS / self.cwnd)
        if (flags & FLAGS_FIN | FLAGS_ACK) == FLAGS_FIN | FLAGS_ACK:
            self.seq_no_esperado += 1
        elif seq_no == self.seq_no_esperado and len(payload) > 0:
            self.seq_no_esperado += len(payload)
            self.callback(self, payload)
            segmento = make_header(dst_port, src_port, self.seq_no, self.seq_no_esperado, FLAGS_ACK)
            segmento = fix_checksum(segmento, dst_addr, src_addr)
            self.servidor.rede.enviar(segmento, src_addr)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        self.dados_total.append(dados)
        while len(dados) > 0:
            payload = dados[:MSS]
            dados = dados[MSS:]
            src_addr, src_port, dst_addr, dst_port = self.id_conexao
            segmento = make_header(dst_port, src_port, self.seq_no, self.seq_no_esperado, FLAGS_ACK)
            segmento = fix_checksum(segmento + payload, dst_addr, src_addr)
            self.servidor.rede.enviar(segmento, src_addr)
            self.enviados[self.seq_no] = (segmento, src_addr, time.time())
            self.seq_no += len(payload)
        self._iniciar_timer()

    def fechar(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        segmento = make_header(dst_port, src_port, self.seq_no, self.seq_no_esperado, FLAGS_FIN)
        segmento = fix_checksum(segmento, dst_addr, src_addr)
        self.servidor.rede.enviar(segmento, src_addr)
        self.seq_no += 1