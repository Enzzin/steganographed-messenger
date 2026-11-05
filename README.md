# Steganographed Messenger

Chat entre duas pessoas com interface gráfica, mensagens e arquivos transportados
por esteganografia em pacotes ICMP. Cada pessoa executa o mesmo `chat.py`, que
envia e recebe em segundo plano enquanto a janela continua disponível.

## Requisitos

- Python 3.10 ou superior, com Tkinter/Tcl/Tk; sem dependências de terceiros.
- Comunicação IPv4 entre as máquinas e ICMP **Echo Reply, tipo 0**, permitido nos dois sentidos.
- Privilégios para abrir sockets raw: administrador no Windows ou root no Linux.

No instalador oficial do Python para Windows, mantenha a opção de Tcl/Tk
habilitada. Em distribuições Linux, pode ser necessário instalar o pacote
`python3-tk` pelo gerenciador de pacotes da distribuição.

No Windows, abra o PowerShell ou o Prompt de Comando como administrador para
executar o programa. Sockets raw exigem privilégios administrativos e a entrega
dos pacotes depende também das regras de firewall. Consulte a
[documentação oficial da Microsoft](https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2).

## Abrir a interface gráfica

```powershell
python chat.py
```

Na janela:

1. Preencha o **IP local** com o endereço deste computador e o **IP remoto** com
   o endereço da outra pessoa.
2. Escolha a pasta para os arquivos recebidos e ajuste as opções de envio, se necessário.
3. Clique em **Abrir sessão**. A outra pessoa faz o mesmo, invertendo os IPs.
4. Digite uma mensagem e pressione **Enter** ou use o botão de envio.

Use **Shift+Enter** para inserir uma nova linha. O botão **Anexar arquivo** abre
o seletor de arquivos. Os arquivos recebidos ficam em `received_files/` por
padrão, ou na pasta escolhida antes de abrir a sessão.

Cada envio mostra seu estado na conversa. **Entregue** indica que a outra
instância confirmou o recebimento completo. **Sem confirmação** indica que as
tentativas terminaram sem essa resposta; a mensagem pode ter chegado se a
confirmação se perdeu.

**Abrir sessão** prepara o envio e a escuta no computador. A confirmação de cada
mensagem informa que houve comunicação com a outra pessoa. Os IPs precisam ser
alcançáveis entre si: firewalls, roteadores e NAT podem impedir esse tráfego.

O botão **Salvar conversa** exporta o histórico para um arquivo de texto.
**Encerrar sessão** cancela os envios ainda pendentes. O histórico fica na
janela durante a execução e pode ser salvo antes de fechar o programa.

## Conversar entre dois computadores

Exemplo na mesma rede: a pessoa A tem IP `192.168.1.10` e a pessoa B tem IP
`192.168.1.20`. Substitua pelos endereços reais nos campos da janela ou passe-os
na linha de comando para preencher os campos automaticamente.

Na máquina A:

```powershell
python chat.py -s 192.168.1.10 -d 192.168.1.20
```

Na máquina B:

```powershell
python chat.py -s 192.168.1.20 -d 192.168.1.10
```

As duas pessoas clicam em **Abrir sessão** e podem enviar e receber ao mesmo
tempo. Os argumentos configuram a janela; a sessão começa pelo botão.

Sem argumentos, o IP local inicial é `0.0.0.0` e o remoto é `127.0.0.1`.
`0.0.0.0` permite escutar nas interfaces locais. Para conversar com outro
computador, informe o endereço dele como IP remoto.

## Testar na mesma máquina

Abra duas instâncias e configure o IP local e o remoto como `127.0.0.1`, ou
execute duas vezes:

```powershell
python chat.py -s 127.0.0.1 -d 127.0.0.1
```

Abra a sessão em ambas as janelas. No Windows, a entrega de ICMP raw em loopback
pode variar conforme o sistema e sua configuração. Se não houver confirmação,
teste entre duas máquinas da mesma rede com ICMP tipo 0 permitido.

## Modo terminal

A interface de terminal continua disponível com `--terminal`. Por exemplo:

```powershell
# Máquina A
python chat.py --terminal -s 192.168.1.10 -d 192.168.1.20

# Máquina B
python chat.py --terminal -s 192.168.1.20 -d 192.168.1.10
```

No Linux, use o executável Python disponível e as permissões necessárias para
abrir o socket, por exemplo `sudo python3 chat.py --terminal ...`.

| Entrada no terminal | Ação |
| --- | --- |
| Texto seguido de Enter | Envia uma mensagem de texto. |
| `/ajuda` | Mostra os comandos disponíveis. |
| `/historico` | Mostra o histórico da sessão. |
| `/arquivo CAMINHO` | Envia um arquivo. |
| `/sair` | Encerra o programa e cancela envios pendentes. |
| `//texto` | Envia uma mensagem que começa com `/`. |

No terminal, use aspas quando o caminho contiver espaços:

```text
/arquivo "C:\Users\Maria\Documents\meu arquivo.pdf"
```

## Opções de execução

As opções abaixo também preenchem as configurações iniciais da interface gráfica.

| Opção | Padrão | Finalidade |
| --- | --- | --- |
| `--terminal` | Desativado | Usa o chat de terminal em vez da janela. |
| `-s`, `--source` | `0.0.0.0` | Endereço IPv4 local para o bind. |
| `-d`, `--destination` | `127.0.0.1` | IP ou nome da máquina de destino. |
| `--intervalo` | `0.005` | Intervalo, em segundos, entre pacotes enviados. |
| `--timeout` | `3` | Tempo, em segundos, para aguardar ACK após o envio. |
| `--tentativas` | `3` | Número máximo de tentativas de envio. |
| `--pasta-recebidos` | `received_files` | Pasta para salvar arquivos recebidos. |

O intervalo aceito vai de 0 a 4 segundos; são permitidas de 1 a 10 tentativas.
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

O programa, a interface gráfica e o protocolo ficam em `chat.py`, que substitui
os antigos `envia_final.py` e `recebe_final.py`. O protocolo atual não é compatível
com as versões anteriores: as duas pessoas precisam usar esta versão do chat.

Execute os testes com:

```bash
python -m unittest discover -s tests -v
```

Os testes verificam o protocolo e o transporte simulado. A comunicação ICMP raw
entre dois computadores depende do sistema operacional e da rede e precisa ser
verificada nesse ambiente.
