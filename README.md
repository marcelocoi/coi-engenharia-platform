<div align="center">

  <img src="src/public_site/LOGO.png" alt="COI Engenharia Logo" width="150" />

  # COI Engenharia - Ecossistema Digital Integrado
  
  **Plataforma Híbrida: Site Institucional de Alta Performance & Intranet de Gestão de Engenharia.**

  [![PHP Version](https://img.shields.io/badge/php-8.0%2B-777BB4?style=for-the-badge&logo=php&logoColor=white)](https://www.php.net/)
  [![Database](https://img.shields.io/badge/MySQL-00000F?style=for-the-badge&logo=mysql&logoColor=white)](https://www.mysql.com/)
  [![Security](https://img.shields.io/badge/Security-CSP%20%7C%20HSTS-success?style=for-the-badge&logo=security&logoColor=white)](#-cybersecurity--compliance)
  [![AI Engine](https://img.shields.io/badge/Gemini_2.0-8E75B2?style=for-the-badge&logo=googlebard&logoColor=white)](https://deepmind.google/technologies/gemini/)
  [![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

  [Visão Geral](#-visão-geral-do-ecossistema) • [Site Público](#-módulo-1-site-institucional-público) • [Intranet](#-módulo-2-intranet-corporativa-restrito) • [Segurança](#-cybersecurity--compliance) • [Instalação](#-instalação)

</div>

---

## 🌐 Visão Geral do Ecossistema

O ecossistema digital da **COI Engenharia** foi desenvolvido para cobrir duas frentes críticas do negócio: a presença digital de alta conversão (Site) e a gestão operacional rigorosa de obras (Intranet).

Ambos os sistemas compartilham a mesma infraestrutura de servidor e banco de dados, mas operam com camadas de segurança e lógicas de acesso distintas, unificados por uma arquitetura **Vanilla PHP** para máxima performance e longevidade.

---

## 📸 Interface do Sistema

| **Site Institucional (Landing Page)** | **Intranet & RDO Digital** |
|:---:|:---:|
| <img src="assets/chat_ia.png" alt="Site Público" width="100%"> | <img src="assets/intranet.png" alt="Dashboard Intranet" width="100%"> |
| *Showcase de obras e Chatbot IA* | *Gestão operacional restrita* |

---

## 🌍 Módulo 1: Site Institucional (Público)

Desenvolvido para ser a vitrine tecnológica da empresa, focado em SEO, velocidade e captação de leads qualificados. O código (`src/public_site/index.php`) implementa proteções avançadas nativamente.

### Funcionalidades Principais:
* **Defense in Depth (Frontend):** Implementação rigorosa de headers de segurança (`Content-Security-Policy`, `X-Frame-Options`, `HSTS`) diretamente no PHP, sem depender de configuração de servidor.
* **Monitoramento de Tráfego:**
    * **Geolocalização:** Integração com API para identificar país/cidade do visitante e bloquear tráfego suspeito.
    * **Log de Visitas:** Registro detalhado de IP, User-Agent e Referer no banco de dados para auditoria.
    * **Contador de Visitas:** Sistema de contagem atômica (file-based locking) para performance sem overload no banco.
* **Formulários Blindados:**
    * **Honeypot Dinâmico:** Campos ocultos que capturam bots de spam sem incomodar o usuário com CAPTCHA.
    * **Anti-CSRF:** Tokens criptográficos rotativos que impedem falsificação de solicitações.
    * **Sanitização:** Limpeza recursiva de todas as entradas (`$_POST`/`$_GET`) contra Injeção de Código.
* **Integração IA:** Interface de chat flutuante conectada ao assistente Gemini para triagem inicial de contatos.

---

## 🏢 Módulo 2: Intranet Corporativa (Restrito)

O "ERP Técnico" da empresa, acessível apenas mediante autenticação, focado na digitalização do canteiro de obras.

### 📋 RDO Digital (Relatório Diário de Obras)
Substituição dos diários de papel por registros digitais auditáveis.
* **Registro Climático:** Monitoramento manhã/tarde.
* **Gestão de Ativos:** Controle de efetivo (Mão de Obra) e Maquinário alocado.
* **Fluxo de Aprovação:** Validação em 3 níveis (Engenheiro > Fiscal > Admin).
* **Evidências:** Galeria de fotos com timestamps.

### 📂 GED (Gestão Eletrônica de Documentos)
* **Interface Windows-like:** Navegação hierárquica por pastas.
* **Bulk Actions:** Upload Drag & Drop e Download ZIP on-the-fly.
* **Auditoria:** Logs de quem baixou ou enviou cada arquivo.

### 📊 Dashboard & BI
* **KPIs:** Gráficos de produtividade e status de relatórios.
* **Segurança:** Monitoramento em tempo real de tentativas de invasão e erros PHP.

### 👥 Gestão de Acessos
* **Autenticação Híbrida:** Login local + Integração IMAP/POP3.
* **RBAC:** Controle de acesso baseado em cargos e obras específicas.

---

## 🛠️ Arquitetura e Stack

O projeto segue princípios de **Clean Code**, priorizando código nativo.

| Camada | Tecnologia | Detalhes Técnicos |
| :--- | :--- | :--- |
| **Linguagem** | **PHP 8.x (Vanilla)** | Sem frameworks pesados. Uso de `Strict Types` e POO. |
| **Banco** | **MySQL / MariaDB** | Driver PDO com Prepared Statements e Transactions. |
| **Frontend** | **HTML5 / CSS3 / JS** | Design System próprio. Site público otimizado para Core Web Vitals. |
| **API** | **REST / cURL** | Integração nativa com APIs externas (Gemini, IP-API). |
| **Server** | **Apache / Nginx** | Configuração via `.htaccess` e headers PHP. |

---

## 🔒 Cybersecurity & Compliance

A segurança é aplicada em camadas, protegendo tanto a vitrine pública quanto os dados restritos.

### No Site Público (`index.php`):
* **Rate Limiting:** Bloqueio temporário de IPs que excedem o limite de requisições (proteção DDoS L7).
* **Session Hardening:** Cookies `HttpOnly`, `Secure` e `SameSite=Strict`.
* **XSS Protection:** Nonces criptográficos para scripts inline e bloqueio de origens externas não autorizadas.
* **Anti-Spam:** Validação de tempo de preenchimento e honeypots.

### Na Intranet:
* **Logs Imutáveis:** Registro de todas as ações críticas (Login, Upload, Delete).
* **Isolamento:** Pasta de uploads (`data/`) fora do acesso direto público quando possível ou protegida via `.htaccess`.
* **Anti-Bruteforce:** Bloqueio de conta após N tentativas falhas.

---

## ⚙️ Instalação

### Pré-requisitos
* PHP 8.0+ (extensões: `pdo`, `curl`, `mbstring`, `zip`, `gd`).
* MySQL 5.7+.

### Passo a Passo

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/marcelocoi/coi-engenharia-platform.git](https://github.com/marcelocoi/coi-engenharia-platform.git)
    ```

2.  **Banco de Dados:**
    * Importe `database/schema.sql`. Ele criará as tabelas tanto para o site (logs de visita) quanto para a intranet (usuários, obras).

3.  **Configuração:**
    * Renomeie `src/config/db_config.example.php` para `db_config.php` e configure as credenciais.
    * Configure o arquivo `.env` na raiz com sua `GEMINI_API_KEY`.

4.  **Estrutura de Pastas:**
    * `/src/public_site`: Aponte o domínio principal (ex: `coiengenharia.com.br`) para cá.
    * `/src/intranet`: Aponte o subdomínio (ex: `intranet.coiengenharia.com.br`) para cá.

---

## 👤 Autor

**Eng. Marcelo de Barros** *CEO da COI Engenharia & Full Stack Developer*

Engenheiro Civil com expertise em grandes obras (Usina Nuclear Angra 3, Rodovias) e desenvolvimento de soluções tecnológicas de alta complexidade.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Conectar-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/company/108664081/) 
[![COI Engenharia](https://img.shields.io/badge/COI_Engenharia-Website_Oficial-0D2C54?style=for-the-badge&logo=google-chrome&logoColor=white)](https://coiengenharia.com.br)

---

<div align="center">
  <sub>Copyright © 2026 COI Engenharia. Todos os direitos reservados.</sub>
</div>
