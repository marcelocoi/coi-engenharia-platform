<div align="center">

  <img src="src/public_site/LOGO.png" alt="COI Engenharia Logo" width="150" />

  # Case Study: Enterprise Architecture & AI-Assisted Development
  
  **A prova técnica de que Sistemas Corporativos de Alta Complexidade, Seguros e Performáticos podem ser construídos com auxílio de IA.**

  [![Security Rating](https://img.shields.io/badge/SecurityHeaders.com-A%2B-success?style=for-the-badge&logo=security&logoColor=white)](https://securityheaders.com/?q=https%3A%2F%2Fcoiengenharia.com.br&followRedirects=on)
  [![PHP Version](https://img.shields.io/badge/php-8.0%2B-777BB4?style=for-the-badge&logo=php&logoColor=white)](https://www.php.net/)
  [![Architecture](https://img.shields.io/badge/Architecture-Vanilla%20MVC-important?style=for-the-badge&logo=architect&logoColor=white)](#-arquitetura-e-filosofia-no-framework)
  [![AI Engine](https://img.shields.io/badge/Built_With-Gemini_2.0_%26_Antigravity-8E75B2?style=for-the-badge&logo=googlebard&logoColor=white)](#-o-desafio-ia-vs-qualidade)

  [O Desafio](#-o-propósito-deste-repositório) • [Segurança Comprovada](#-segurança-militar-defense-in-depth) • [Ecossistema](#-ecossistema-técnico) • [Intranet](#-módulo-restrito-intranet--rdo) • [Convite à Análise](#-convite-aos-code-reviewers)

</div>

---

## 🎯 O Propósito Deste Repositório

> *"A IA escreve código inseguro."*
> *"Aplicativos gerados por IA não servem para produção."*
> *"Você precisa de um Framework pesado para ter segurança."*

Este repositório foi tornado público para **desafiar essas afirmações**.

O código aqui presente sustenta a operação real da **COI Engenharia**, gerenciando contratos de infraestrutura pesada para clientes como **Grupo Assaí e EIXO-SP**. Ele foi construído utilizando Inteligência Artificial (Gemini/Antigravity) como acelerador de produtividade, mas sob estrita supervisão de engenharia de software.

**O resultado?** Um sistema que supera a maioria dos CMSs e Frameworks padrões em testes de segurança e performance, provando que a qualidade do software depende da arquitetura e do direcionamento, não apenas de quem (ou o que) digita o código.

---

## 🛡️ Segurança Militar (Defense in Depth)

A segurança não é um "plugin" instalado no final. Ela é nativa da aplicação. O site obteve nota máxima em auditorias externas, superando grandes portais corporativos.

### 🏆 Evidências de Auditoria
* **SecurityHeaders.com:** Grade **A+** [[Ver Relatório](https://securityheaders.com/?q=https%3A%2F%2Fcoiengenharia.com.br&followRedirects=on)]
* **CoreNexis:** Score de Compliance Total [[Ver Relatório](https://tools.corenexis.com/web/security-headers)]

*(Insira aqui o print do SecurityHeaders A+ se desejar: `![Security Score](assets/security_score.png)`)*

### Implementação Técnica (Hardening)
Diferente de frameworks que mascaram a segurança, aqui implementamos "na unha" (Vanilla PHP):

1.  **CSP (Content Security Policy) Rigorosa:**
    * Definimos uma whitelist estrita de origens.
    * Uso de **Nonces Criptográficos** (`nonce-base64string`) gerados dinamicamente a cada requisição para permitir scripts inline específicos, anulando ataques XSS comuns.
    
2.  **Proteção de Sessão e Identidade:**
    * `SameSite=Strict`, `HttpOnly` e `Secure` forçados via PHP (não apenas .htaccess).
    * **Session Regeneration:** O ID da sessão é regenerado periodicamente e em mudanças de privilégio para evitar *Session Fixation*.
    * **HSTS (HTTP Strict Transport Security):** Força navegadores a recusarem conexões não criptografadas.

3.  **Blindagem de Formulários:**
    * **Honeypot Dinâmico:** Campos invisíveis (`display: none` ou off-screen) com nomes atraentes para bots (`email_check`, `website`). Se preenchido, o request é descartado silenciosamente.
    * **Anti-CSRF:** Tokens únicos validados em `POST`.

---

## 🏗️ Arquitetura e Filosofia "No-Framework"

Por que **Vanilla PHP** em 2026?

1.  **Performance Pura:** O *overhead* de carregar bibliotecas gigantes (como Vendor do Laravel/Symfony) é zero. O *Time-to-First-Byte* (TTFB) é otimizado para conexões 3G/4G comuns em canteiros de obras.
2.  **Auditoria de IA:** Ao não usar abstrações mágicas de frameworks, a IA (e o programador) é forçada a escrever a lógica de conexão (`PDO`), roteamento e segurança explicitamente, tornando o código mais transparente para auditoria.
3.  **Longevidade:** O código não quebra porque o framework atualizou da versão 10 para a 11. É PHP Standard.

---

## 🌍 Ecossistema Técnico

O sistema é dividido em dois núcleos que compartilham o mesmo banco de dados, mas operam em contextos de segurança distintos.

### 1. Site Institucional (Frontend Público)
*Foco: SEO, Performance, Conversão.*
* **Load Time:** Otimizado para Core Web Vitals.
* **Geolocalização:** Integração nativa com API para bloquear tráfego de países fora da área de atuação (Defense Layer 1).
* **IA Chat:** Widget flutuante integrado ao **Gemini 2.0 Flash** via API REST (cURL) para triagem comercial sem expor chaves no frontend.

### 2. Intranet Corporativa (Backend Restrito)
*Foco: Regra de Negócio, Integridade de Dados, Auditoria.*
* **RDO (Relatório Diário de Obra):** O coração do sistema. Digitaliza o controle de efetivo, maquinário e clima.
* **GED (Gestão Eletrônica de Documentos):** Sistema de arquivos virtual com permissões (RBAC) e download em lote (ZipStream).
* **Logs Imutáveis:** Cada ação (Login, Upload, Delete, Edit) é registrada com IP, User-Agent e Timestamp.

---

## 📸 Screenshots do Sistema Real

| **Dashboard Operacional** | **Inteligência Artificial Integrada** |
|:---:|:---:|
| <img src="assets/intranet.png" alt="Dashboard Intranet" width="100%"> | <img src="assets/chat_ia.png" alt="Chatbot Gemini" width="100%"> |
| *Visão gerencial em tempo real* | *Assistente treinado com contexto da empresa* |

---

## 👨‍💻 Convite aos Code Reviewers

Se você chegou aqui através do vídeo sobre a criação deste sistema: **Bem-vindo.**

Convido você a analisar a pasta `/src`. Você não encontrará pastas `vendor` gigantescas ou arquivos de configuração obscuros. Você encontrará:
1.  **`db_config.php`:** Conexão Singleton segura com PDO.
2.  **`index.php`:** Roteamento e aplicação de Headers de Segurança antes de qualquer output.
3.  **`chat_api.php`:** Como consumir APIs de LLM (Gemini) de forma segura no backend (Server-to-Server) sem expor tokens no cliente.

Este projeto prova que a **Inteligência Artificial**, quando guiada por um profissional que entende os fundamentos da Engenharia de Software, é capaz de entregar produtos de nível Enterprise.

---

## ⚙️ Instalação (Para Análise)

### Pré-requisitos
* PHP 8.0+
* MySQL 5.7+

### Setup
1.  **Clone o repo:**
    ```bash
    git clone [https://github.com/marcelocoi/coi-engenharia-platform.git](https://github.com/marcelocoi/coi-engenharia-platform.git)
    ```
2.  **Banco de Dados:**
    * Importe `database/schema.sql`.
3.  **Configuração:**
    * Renomeie `src/config/db_config.example.php` para `db_config.php`.
    * Crie um `.env` com sua `GEMINI_API_KEY`.

---

## 👤 Autor

**Eng. Marcelo de Barros**
*CEO da COI Engenharia | Desenvolvedor Full Stack*

Liderando a transformação digital na construção civil pesada através de código proprietário e seguro.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Conectar-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/company/108664081/) 
[![COI Engenharia](https://img.shields.io/badge/COI_Engenharia-Website_Oficial-0D2C54?style=for-the-badge&logo=google-chrome&logoColor=white)](https://coiengenharia.com.br)

---

<div align="center">
  <sub>Copyright © 2026 COI Engenharia. Todos os direitos reservados.</sub>
</div>
