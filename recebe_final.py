import socket
import struct
import sys

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
ORIGEM = "127.0.0.1"

#Mapa para pegar a extensao de volta atraves do codigo
MAPA_EXTENSAO = {
    0x0: "bin", 0x1: "jpg", 0x2: "png", 0x3: "pdf",
    0x4: "zip", 0x5: "txt", 0x6: "bmp", 0x7: "gif",
    0x8: "mp3", 0x9: "wav", 0xA: "mp4", 0xB: "doc",
    0xC: "py",  0xD: "tar",
}

def decodifica_byte(byte_estego: int) -> dict:
    #Tira cada bit usando deslocamento >> e usa & 1 para pegar somente o bit certo em caso de erro de comunicação
    ctx = (byte_estego >> 7) & 1
    seq_cmd = (byte_estego >> 6) & 1
    part_sub = (byte_estego >> 5) & 1
    parity = (byte_estego >> 4) & 1
    nibble = byte_estego & 0x0F

    return {
        "ctx": ctx,
        "seq_cmd": seq_cmd,
        "part_sub": part_sub,
        "parity": parity,
        "nibble": nibble,
    }

def valida_paridade(nibble: int, parity_bit: int) -> bool:
    paridade_esperada = bin(nibble).count("1") % 2
    if paridade_esperada != parity_bit:
        return 0
    else:
        return 1

print(f"Escutando em {ORIGEM} e esperando pacotes")

#configurando flags iniciais
recebendo = False
buffer_arquivo = bytearray()
nibble_alto_temp = None
tamanho_esperado = 0
extensao_arquivo = "bin"
seq_esperada = 0 

#Guardando os 6 nibbles do tamanho do arquivo
nibbles_tamanho = []
recebendo_tamanho = False

#Contador de pacotes para controle
pacotes_dados = 0
pacotes_ignorados = 0

#Inicio real da comunicacao
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
    s.bind((ORIGEM, 0))

    while True:
        #Recebe os dados do socket raw (pacote com cabecalho IP + ICMP + payload)
        dados, endereco = s.recvfrom(1024)

        #Desempacota o cabecalho ICMP que comeca no byte 20 depois do cabecalho IP de 20 bytes
        tipo, codigo, checksum, _id, seq = struct.unpack(FORMATO, dados[20:28])

        #Filtra so pacotes ICMP Echo Reply (tipo 0), ignora outros tipos como request (tipo 8)
        if tipo != 0:
            continue

        #Garante que o pacote tem pelo menos 29 bytes (20 do IP + 8 do cabecalho ICMP + 1 do payload modificado)
        if len(dados) < 29:
            continue

        #Pega so o primeiro byte do payload onde esta o dado oculto
        byte_estego = dados[28]

        #Decodifica os bits do byte recebido
        campos = decodifica_byte(byte_estego)
        ctx      = campos["ctx"]
        seq_cmd  = campos["seq_cmd"]
        part_sub = campos["part_sub"]
        parity   = campos["parity"]
        nibble   = campos["nibble"]

        #Se for pacote de CONTROLE (Bit 7 == 1)
        if ctx == CTX_CTRL:

            #Nos pacotes de controle o bit de validacao (bit 4) deve ser 1 fixo para confirmar que e nosso
            if parity != 1:
                pacotes_ignorados += 1
                continue

            #Comando de START (inicio de transmissao)
            if seq_cmd == CMD_START:

                #Parte de receber o tamanho do arquivo (sub comando tamanho)
                if part_sub == SUB_TAMANHO and len(nibbles_tamanho) < 6:
                    if not recebendo_tamanho and not recebendo:
                        recebendo_tamanho = True
                        nibbles_tamanho = []
                        buffer_arquivo = bytearray()
                        nibble_alto_temp = None
                        seq_esperada = 0
                        pacotes_dados = 0
                        print("\nPacote START recebido - Iniciando sessao")

                    #Acumula o nibble do tamanho
                    if recebendo_tamanho:
                        nibbles_tamanho.append(nibble)

                        #Quando juntar os 6 nibbles remonta o tamanho total do arquivo
                        if len(nibbles_tamanho) == 6:
                            tamanho_esperado = 0
                            for nib in nibbles_tamanho:
                                tamanho_esperado = (tamanho_esperado << 4) | (nib & 0x0F)
                            recebendo_tamanho = False
                            print(f"Tamanho esperado do arquivo: {tamanho_esperado} bytes")

                #Parte de receber a extensao do arquivo (sub comando extensao)
                elif part_sub == SUB_EXTENSAO:
                    codigo_ext = nibble
                    extensao_arquivo = MAPA_EXTENSAO.get(codigo_ext, "bin")
                    recebendo = True #Agora pode comecar a receber os dados
                    print(f"Extensao recebida: .{extensao_arquivo} (codigo: 0x{codigo_ext:X})")
                    print("\nRecebendo dados do arquivo...")

            #Comando de END (fim de transmissao)
            elif seq_cmd == CMD_END:

                #Verifica se o nibble tem o numero magico correto para confirmar o fim
                if nibble != MAGIC_NIBBLE:
                    pacotes_ignorados += 1
                    continue

                print("\nPacote de fim (END) recebido - Finalizando recepcao")

                #Caminho do arquivo onde salvar, passado direto na CLI
                #se tiver passado
                if len(sys.argv) > 1:
                    caminho_salvar = sys.argv[1]
                else:
                    caminho_salvar = f"recebido.{extensao_arquivo}"

                #wb salva em modo binario para nao corromper arquivos como imagens ou executaveis
                with open(caminho_salvar, "wb") as f:
                    f.write(buffer_arquivo)

                tamanho_recebido = len(buffer_arquivo)

                print("=" * 50)
                print("Recepcao concluida com sucesso!")
                print(f"Arquivo salvo como: {caminho_salvar}")
                print(f"Bytes recebidos:    {tamanho_recebido}")
                print(f"Bytes esperados:    {tamanho_esperado}")
                print(f"Pacotes de dados:   {pacotes_dados}")
                print(f"Pacotes ignorados:  {pacotes_ignorados}")

                #Verificacao simples de integridade
                if tamanho_recebido == tamanho_esperado:
                    print("Integridade: OK (tamanhos batem perfeitamente)")
                else:
                    print(f"Integridade: ALERTA (diferenca de {abs(tamanho_esperado - tamanho_recebido)} bytes)")
                print("=" * 50)

                break

        #Se for pacote de DADOS (Bit 7 == 0)
        elif ctx == CTX_DATA:

            #So processa pacotes de dados se a sessao ja tiver sido iniciada pelo START
            if not recebendo:
                pacotes_ignorados += 1
                continue

            #Verificacao de paridade para saber se o nibble chegou corrompido
            if not valida_paridade(nibble, parity):
                pacotes_ignorados += 1
                continue

            pacotes_dados += 1

            #Se for o nibble alto (bits 7 ao 4)
            if part_sub == PART_HIGH:
                nibble_alto_temp = nibble

            #Se for o nibble baixo (bits 3 ao 0)
            elif part_sub == PART_LOW:
                if nibble_alto_temp is not None:
                    #Junta o nibble alto e o baixo para montar o byte original do arquivo
                    byte_completo = (nibble_alto_temp << 4) | nibble
                    buffer_arquivo.append(byte_completo)

                    #Limpa o temporario para o proximo byte
                    nibble_alto_temp = None

                    #Inverte o bit de sequencia esperado usando XOR
                    seq_esperada ^= 1

                    #Prints de progresso a cada 10%
                    bytes_recebidos = len(buffer_arquivo)
                    passo_10_porcento = max(1, tamanho_esperado // 10)
                    fim = (bytes_recebidos == tamanho_esperado)

                    if (bytes_recebidos % passo_10_porcento == 0) or fim:
                        if tamanho_esperado > 0:
                            porcentagem = (bytes_recebidos / tamanho_esperado) * 100
                            print(f"{bytes_recebidos}/{tamanho_esperado} bytes recebidos: {porcentagem:.2f}% já recebidos")
