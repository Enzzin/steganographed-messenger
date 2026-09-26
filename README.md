<div align="center">

# 🕵️‍♂️ Steganographed Messenger 🛰️

<p align="center">
  <em>Envio e recebimento de dados ocultos via pacotes de rede com esteganografia</em> ✨
</p>

[![Status: Under Development](https://img.shields.io/badge/status-under%20development-f39c12?style=for-the-badge&logo=git&logoColor=white)](https://github.com/)
[![Python Version](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](./LICENSE)

---

### 🚧 **EM DESENVOLVIMENTO / UNDER DEVELOPMENT** 🚧

> ⚠️ **Aviso:** Este projeto está atualmente sob desenvolvimento ativo! Novas funcionalidades, melhorias de protocolo e refatorações estão a caminho. 🛠️

</div>

---

## 🔮 Sobre o Projeto

O **Steganographed Messenger** é uma ferramenta para transmissão furtiva de mensagens e arquivos através de canais encobertos em pacotes de rede, utilizando técnicas de esteganografia em nível de nibble e bits de controle/paridade.

### 🌟 Destaques & Funcionalidades

- 🔒 **Canal Oculto (Covert Channel):** Codificação de dados disfarçados em campos de cabeçalho de rede.
- 🧩 **Fragmentação por Nibble:** Divisão inteligente dos bytes em partes alta e baixa com paridade calculada.
- ⚡ **Controle de Congestionamento:** Múltiplas taxas de atraso configuráveis para evasão e estabilidade.
- 📁 **Suporte a Arquivos & Mensagens:** Envio e reconstrução íntegra na ponta receptora.

---

## 📦 Estrutura dos Arquivos

| Arquivo | Descrição | Status |
| :--- | :--- | :---: |
| 🚀 [`envia_final.py`](./envia_final.py) | Módulo emissor dos pacotes esteganografados | 🟡 Em testes |
| 📥 [`recebe_final.py`](./recebe_final.py) | Módulo receptor e reconstrutor de payload | 🟡 Em testes |
| 📜 [`LICENSE`](./LICENSE) | Termos de licença MIT | 🟢 Ativo |
| 🙈 [`.gitignore`](./.gitignore) | Regras de exclusão do Git | 🟢 Ativo |

---

## 🚀 Como Executar (Preview)

> 💡 **Nota:** Para manipular pacotes brutos (*raw packets*), podem ser necessários privilégios de administrador/root.

```bash
# Receptor (em um terminal / máquina)
python recebe_final.py

# Emissor (em outro terminal / máquina)
python envia_final.py
```

---

<div align="center">

Feito com ☕ e curiosidade por segurança ofensiva/defensiva 💻✨

</div>
