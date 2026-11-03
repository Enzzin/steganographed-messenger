# Steganographed Messenger

Chat de terminal entre duas pessoas com mensagens e arquivos transportados por
esteganografia em pacotes ICMP. Cada pessoa executa o mesmo `chat.py`, que envia
e recebe em segundo plano enquanto o terminal aceita novas mensagens.

## Requisitos

- Python 3.10 ou superior, somente com a biblioteca padrão.
- Comunicação IPv4 entre as máquinas e ICMP **Echo Reply, tipo 0**, permitido nos dois sentidos.
- Terminal como administrador no Windows ou `sudo` no Linux para abrir sockets raw.

No Windows, abra o PowerShell ou o Prompt de Comando como administrador.
Sockets raw exigem privilégios administrativos e a entrega dos pacotes depende
também das regras de firewall. Consulte a
[documentação oficial da Microsoft](https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2).

## Conversar entre dois computadores

Exemplo na mesma rede: a pessoa A tem IP `192.168.1.10` e a pessoa B tem IP
`192.168.1.20`. Substitua pelos endereços reais.

Na máquina A:

```powershell
python chat.py -s 192.168.1.10 -d 192.168.1.20
```

Na máquina B:

```powershell
python chat.py -s 192.168.1.20 -d 192.168.1.10
```

No Linux, acrescente `sudo` e use o executável Python disponível, por exemplo:

```bash
sudo python3 chat.py -s 192.168.1.10 -d 192.168.1.20
```

`-s` indica o IP local; `-d` indica o IP da outra pessoa. Com ambos os programas
abertos, digite uma mensagem e pressione Enter. As duas pessoas podem enviar e
receber ao mesmo tempo.

Os IPs precisam ser alcançáveis entre si. Estar conectado à internet não garante
comunicação direta: firewalls, roteadores e NAT podem impedir esse tráfego.

## Testar na mesma máquina

Abra dois terminais com as permissões necessárias e execute, em cada um:

```powershell
python chat.py -s 127.0.0.1 -d 127.0.0.1
```

No Windows, a entrega de ICMP raw em loopback pode variar conforme o sistema e
sua configuração. Se não houver confirmação, teste entre duas máquinas da
mesma rede com ICMP tipo 0 permitido.

Sem argumentos, `python chat.py` escuta em `0.0.0.0` e envia para `127.0.0.1`.
Para conversar com outra máquina, informe o destino com `-d`.

## Comandos do chat

| Entrada | Ação |
| --- | --- |
| Texto seguido de Enter | Envia uma mensagem de texto. |
| `/ajuda` | Mostra os comandos disponíveis. |
| `/historico` | Mostra o histórico da sessão. |
| `/arquivo CAMINHO` | Envia um arquivo. |
| `/sair` | Encerra o programa. |
| `//texto` | Envia uma mensagem que começa com `/`. |

Use aspas quando o caminho contiver espaços:

```text
/arquivo "C:\Users\Maria\Documents\meu arquivo.pdf"
```

Os arquivos recebidos ficam em `received_files/` por padrão. O histórico é
mantido em memória durante a sessão.

## Opções de execução

| Opção | Padrão | Finalidade |
| --- | --- | --- |
| `-s`, `--source` | `0.0.0.0` | Endereço IPv4 local para o bind. |
| `-d`, `--destination` | `127.0.0.1` | IP ou nome da máquina de destino. |
| `--intervalo` | `0.005` | Intervalo, em segundos, entre pacotes enviados. |
| `--timeout` | `3` | Tempo, em segundos, para aguardar ACK após o envio. |
| `--tentativas` | `3` | Número máximo de tentativas de envio. |
| `--pasta-recebidos` | `received_files` | Pasta para salvar arquivos recebidos. |

O intervalo aceito vai de 0 a 4 segundos; são permitidas de 1 a 10 tentativas.
`/sair` cancela os envios ainda pendentes.

Consulte `python chat.py --help` para a ajuda da linha de comando.

## Como funciona

O programa oculta dados no primeiro byte do payload de pacotes ICMP Echo Reply.
Cada byte da mensagem é dividido em dois nibbles de quatro bits, enviados em
pacotes distintos. A recepção verifica a sequência e a integridade com CRC32
antes de confirmar a entrega com um ACK. Há retransmissões limitadas e
identificação de mensagens repetidas para evitar exibi-las novamente quando
uma confirmação se perde.

O limite por transmissão é de aproximadamente 16 MiB, incluindo envelope e
metadados; o tamanho máximo de um arquivo é ligeiramente menor. Como cada byte
exige dois pacotes, arquivos grandes podem levar bastante tempo.

A esteganografia oculta a representação dos dados, mas **não oferece criptografia
nem autenticação**. O CRC32 detecta erros; não comprova a identidade do remetente.

## Estrutura e testes

`chat.py` substitui os antigos `envia_final.py` e `recebe_final.py`. O protocolo
atual não é compatível com as versões anteriores: as duas pessoas precisam
usar esta versão do chat.

Execute os testes com:

```bash
python -m unittest discover -s tests -v
```

Os testes verificam o protocolo e o transporte simulado. A comunicação ICMP raw
entre dois computadores depende do sistema operacional e da rede e precisa ser
verificada nesse ambiente.
