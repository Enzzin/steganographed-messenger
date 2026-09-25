import socket
import struct
import os
import sys
import time

FORMATO = "!BBHHH"

#Definindo as variaveis globais

MAGIC_NIBBLE = 0x0B #Numero magico para bytes de controle

# Bit 7: pacote é de DADOS ou de CONTROLE
CTX_DATA = 0  # Pacote de dados 
CTX_CTRL = 1  # Pacote de controle

# Bit 6: comando de stat ou stop
CMD_START = 0 # comando inicio
CMD_END = 1 # comando fim

# Bit 5: nibble
PART_HIGH = 0 #Nibble alto
PART_LOW = 1 #Nibble baixo

# Bit 5: Controle
SUB_TAMANHO = 0 # Tamanho do arquivo
SUB_EXTENSAO = 1 # Extensão do arquivo

#Colocar quando eu criar os containers
ORIGEM  = "127.0.0.1"
DESTINO = "127.0.0.1"

mensagem = (
    b"\b\t\n\v\f\r\016\017\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037 !\"#$%&'()*+,-./01234567"
)
#Evitar Congestinamento (Menu para selecionar)
PAUSA_ENTRE_PACOTES = 0.005

#Montar pacotes de dados
def monta_byte_dados(seq_bit: int, part: int, nibble: int) -> int:
    #A paridade não é passada pelo programa e sim calculada dependendo dos bits 3 ap 0 
    paridade = bin(nibble).count("1") % 2
    #O byte de dados montado passando que o CTX é 0, a seq de bits já calculada anteriormente pela outra função, qual o nibble, paridade calculada por essa função usando o nibble e realemnte o nibble a ser passado
    byte_montado = (CTX_DATA << 7) | (seq_bit << 6) | (part << 5) | (paridade << 4) | (nibble & 0x0F)
    return byte_montado

# Motar pacotes de controle
def monta_byte_controle(cmd: int, sub: int)-> int:
    #O byte de controle montado passsando que o CTX é 1, qual o comando, qual o sub comando, passando 1 para provar q é valido e o magic number ou ext/tamanho do arquivo
    byte_montado = (CTX_CTRL << 7) | (cmd << 6) | (sub << 5) | (1 << 4) | (MAGIC_NIBBLE & 0x0F)
    return byte_montado

#Criação do pacote + Checksum, codigo original só muda o tipo de 8 para 0 pq no pdf pede para usar o Reply e nao request request = 8 e reply = 0 
def cria_icmp(payload: bytearray, sequence: int) -> bytearray:
    tipo = 0 
    codigo = 0
    checksum = 0

    #O sequence e o id usam % 65536 pq o campo H do ICMP so vai ate 65535, se passar disso da erro no struct entao assim ele zera e continua enviando
    identifier = os.getpid() % 65536
    sequence = sequence % 65536

    cabecalho = struct.pack(FORMATO, tipo, codigo, checksum, identifier, sequence)

    pacote = cabecalho + payload
    tamanho_pacote = len(pacote)
    n = 2

    if tamanho_pacote % 2:
        pacote += b"\x00"

    for i in range(0, tamanho_pacote, n):
        palavra = pacote[i:i + n]
        checksum += int.from_bytes(palavra, byteorder="big")

    while checksum >> 16:
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = (~checksum) & 0xFFFF

    cabecalho = struct.pack(FORMATO, tipo, codigo, checksum, identifier, sequence)
    pacote = cabecalho + payload
    return pacote

#Coloca o byte no apayload e envia o pacote
def envia_pacote(sock, byte_alterado: int, seq_icmp: int) -> None:
    payload_oculto = bytearray(mensagem)

    #altera só o byte 0 deixa os outros iguais o original
    payload_oculto[0] = byte_alterado

    pacote = cria_icmp(payload_oculto, seq_icmp)

    sock.sendto(pacote, (DESTINO, 0))

#Caminho do arquivo que vai ser enviado, passado direto na CLI
#se tiver passado
if len(sys.argv) > 1:
    caminho_arq = sys.argv[1]
else:
    caminho_arq = "teste.png"

#rb abre e raw binary sem codificação de texto assim que os bytes sejam tratados corretamente
with open(caminho_arq, "rb") as f:
    dados_arq = f.read()

tamanho_arq = len(dados_arq)

#pegando a extensao do arquivo e removendo o .
extensao = os.path.splitext(caminho_arq)[1].lstrip(".")

MAPA_EXTENSAO = {
    "bin": 0x0, "jpg": 0x1, "jpeg": 0x1, "png": 0x2, "pdf": 0x3,
    "zip": 0x4, "txt": 0x5, "bmp": 0x6, "gif": 0x7, "mp3": 0x8,
    "wav": 0x9, "mp4": 0xA, "doc": 0xB, "py":  0xC, "tar": 0xD,
}

codigo_extensao = MAPA_EXTENSAO.get(extensao.lower(), 0x0) #padrao binario

print("Iniciado a transmissão dos arquivos")
print(f"Arquivo: {caminho_arq}")
print(f"Tamanho: {tamanho_arq} bytes")
print(f"Extensão: {extensao} (código: 0x{codigo_extensao:X})")
print(f"Destino:   {DESTINO}")
print(f"{tamanho_arq * 2} pacotes DADOS")

#Contador de pacotes enviados
qnt_pacotes = 0 

#Inicio real da comunicação
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
    s.bind((ORIGEM, 0))

    print("\nIniciando a primeira parte do envio dos dados, enviado START e metadados")

    #Para caber arquivos maiores até 16mb ao invez de passar somente em 2 nibbles o tamanho do arquivo será passado 6 nibbles para compor o tamanho do arquivo
    nibbles_tamanho = []
    temp_tam = tamanho_arq
    for i in range(6):
        #pegando só os 4 mais baixos e movendo para o lado para depois pegar os outros
        nibbles_tamanho.append(temp_tam & 0x0F)
        temp_tam >>= 4
    nibbles_tamanho.reverse() #inverte os bits para ficar certo

    #Envindo o primeiro byte de controle de tamanho e definindo o tamanho do arquivo
    for nibble_tam in nibbles_tamanho:
        byte_ctrl = monta_byte_controle(CMD_START, SUB_TAMANHO)
        #Substitui os bits do 7 ao 4 com os gerados pela função de montar byte e os bits 3 ao 0 com o nibble do tamanho
        byte_ctrl = (byte_ctrl & 0xF0) | (nibble_tam & 0x0F)
        qnt_pacotes += 1
        envia_pacote(s, byte_ctrl, qnt_pacotes)
        time.sleep(PAUSA_ENTRE_PACOTES)

    print(f"Tamanho total dos 6 nibble enviados {tamanho_arq}")

    #Enviando o segundo Start e definindo a extensão do arquivo parecida com a de cima mas com a diferença da extensao e nao o tamanho 
    byte_ext = monta_byte_controle(CMD_START, SUB_EXTENSAO)
    #Substitui os bits do 7 ao 4 com os gerados pela função de montar byte e os bits 3 ao 0 com o codigo da extensão do arquivo
    byte_ext = (byte_ext & 0xF0) | (codigo_extensao & 0x0F)
    qnt_pacotes += 1
    envia_pacote(s, byte_ext, qnt_pacotes)
    time.sleep(PAUSA_ENTRE_PACOTES)

    print(f"Extensao {extensao} enviada como código 0x{codigo_extensao:x}")

    #Enviando o arquivo propiamente dito
    print(f"\nEnviando {tamanho_arq} bytes do arquivo")

    #criando a variavel de sequencia que começa em 0 
    seq_bit = 0

    #Calculando para os prints de progresso
    passo_10_porcento = max(1, tamanho_arq // 10)

    #iterando sobre todos os bytes do arquivo lido e enviando eles nibble a nibble
    for indice_byte, byte_arquivo in enumerate(dados_arq):
        #pegando os 4 bits mais significativos do 7 ao 4 e movendo eles para o lugar dos bits 3 ao 0 "Limpando o cemeço"
        nibble_alto = (byte_arquivo >> 4) & 0X0F
        #Usando a função ja criada para montar o pacote de dados
        byte_high = monta_byte_dados(seq_bit, PART_HIGH, nibble_alto)
        qnt_pacotes += 1
        envia_pacote(s, byte_high, qnt_pacotes)
        time.sleep(PAUSA_ENTRE_PACOTES)

        #igual o de cima mas para os nibbles mais baixos
        #pegando limpando o começo para manter só os bits 3 ao 0 nao tem que mover porque eles ja estão na posição correta
        nibble_baixo = byte_arquivo & 0x0F
        #Usando a função ja criada para montar o pacote de dados
        byte_low = monta_byte_dados(seq_bit, PART_LOW, nibble_baixo)
        qnt_pacotes += 1
        envia_pacote(s, byte_low, qnt_pacotes)
        time.sleep(PAUSA_ENTRE_PACOTES)

        #Usando um XOR para quando tiver em 1 mudar para 0 e quando tiver em 0 mudar para 1
        seq_bit ^= 1 

        #Prints de progresso a cada 10%
        bytes_enviados = indice_byte + 1
        fim = (bytes_enviados == tamanho_arq)

        #Prinrt do envio a cada 10%
        if (bytes_enviados % passo_10_porcento == 0) or fim:
            porcentagem = (bytes_enviados / tamanho_arq) * 100
            print(f"{bytes_enviados}/{tamanho_arq} bytes enviados: {porcentagem:.2f}% já enviados")

    print("Etapa final: Enviando o comando de fim de transmissão para o recebe.py")

    byte_end = monta_byte_controle(CMD_END, 0)
    qnt_pacotes += 1
    envia_pacote(s, byte_end, qnt_pacotes)

    print("Pacote de fim enviado com sucesso")
    print("Transmissão concluida")
