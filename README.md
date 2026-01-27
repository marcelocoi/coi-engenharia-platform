<div align="center">

  <img src="src/public_site/LOGO.png" alt="COI Engenharia Logo" width="120" />

  # COI Engenharia - Plataforma Corporativa Enterprise
  
  **Sistema Integrado de Gestão de Obras, GED e Intranet com Inteligência Artificial. - https://coiengenharia.com.br/**

  [![PHP Version](https://img.shields.io/badge/php-8.0%2B-777BB4?style=for-the-badge&logo=php&logoColor=white)](https://www.php.net/)
  [![Database](https://img.shields.io/badge/MySQL-00000F?style=for-the-badge&logo=mysql&logoColor=white)](https://www.mysql.com/)
  [![AI Engine](https://img.shields.io/badge/Gemini_2.0-8E75B2?style=for-the-badge&logo=googlebard&logoColor=white)](https://deepmind.google/technologies/gemini/)
  [![Security](https://img.shields.io/badge/Security-CSP%20%7C%20HSTS-success?style=for-the-badge&logo=security&logoColor=white)](#security)
  [![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

  [Ver Funcionalidades](#-funcionalidades) • [Instalação](#-instalação) • [Segurança](#-segurança-e-compliance) • [Contato](#-autor)

</div>

---

## 🚀 Sobre o Projeto

Esta plataforma foi desenvolvida para atender às demandas de alta complexidade da **COI Engenharia**, uma empresa especializada em obras industriais e infraestrutura pesada. 

Diferente de CMSs padrões, este sistema foi construído **do zero (Vanilla PHP)** pelo Antigravity focando em performance extrema, segurança granular ("Defense in Depth") e integração nativa com Inteligência Artificial para suporte operacional.

### 📸 Screenshots

| **Dashboard da Intranet** | **Chatbot com IA (Gemini)** |
|:---:|:---:|
| <img src="assets/intranet.png" alt="Dashboard" width="100%"> | <img src="assets/chat_ia.png" alt="Chatbot" width="100%"> |
| *Visão geral de obras e métricas* | *Assistente virtual contextualizado* |

| **Engenharia de Código** |
|:---:|
| <img src="assets/1.png" alt="VS Code" width="100%"> |
| *Estrutura do código e implementação* |

---

## 🛠️ Stack Tecnológica

O projeto segue a filosofia **Clean Architecture**, evitando dependências excessivas de frameworks para garantir longevidade e controle total do código.

* **Backend:** PHP 8.x (Puro/Vanilla) com Arquitetura MVC.
* **Database:** MySQL / MariaDB (Driver PDO com Prepared Statements).
* **Frontend:** HTML5, CSS3 (Design System Próprio), JavaScript ES6+.
* **AI Core:** Integração via REST API com **Google Gemini 2.0 Flash**.
* **Infra:** Compatível com Apache/Nginx (Linux/Windows Server).

---

## ✨ Funcionalidades Principais

### 🧠 1. Inteligência Artificial Integrada
Implementação de um **Agente de IA Corporativo** utilizando a API do Google Gemini.
* **Contexto Dinâmico:** A IA "conhece" as obras, normas da empresa e dados de contato através de System Prompting avançado.
* **Atuação:** Responde dúvidas técnicas, auxilia na navegação e filtra contatos comerciais.

### 🏗️ 2. Módulo de Engenharia (RDO Digital)
Sistema completo para o **Relatório Diário de Obra**, eliminando papel.
* Registro de efetivo (mão de obra) e maquinário.
* Log de condições climáticas (manhã/tarde).
* Galeria de fotos integrada com upload múltiplo.
* Fluxo de aprovação por engenheiros seniores.

### 📂 3. GED (Gestão Eletrônica de Documentos)
Um "Windows Explorer" via web para gestão de arquivos técnicos.
* Navegação por pastas em árvore.
* Upload assíncrono (AJAX).
* **Bulk Actions:** Download de múltiplos arquivos zipados on-the-fly.
* Permissões baseadas em cargos (RBAC).

---

## 🔒 Segurança e Compliance

A segurança não é um "plugin", mas parte da arquitetura. O sistema implementa **Defense in Depth**:

| Camada | Tecnologia Implementada | Descrição |
| :--- | :--- | :--- |
| **Browser** | **CSP Rigorosa** | `Content-Security-Policy` bloqueia scripts não autorizados (XSS). |
| **Transporte** | **HSTS** | `Strict-Transport-Security` força conexões HTTPS criptografadas. |
| **Sessão** | **Session Hardening** | Cookies `HttpOnly`, `Secure` e proteção contra Session Fixation. |
| **Aplicação** | **Anti-CSRF** | Tokens criptográficos dinâmicos em todos os formulários. |
| **Bot** | **Honeypot & Rate Limit** | Bloqueio de bots sem CAPTCHA intrusivo e limite de requisições por IP. |
| **Dados** | **Sanitização** | Filtros recursivos em Inputs e Prepared Statements (SQL Injection). |

---

## ⚙️ Instalação e Configuração

### Pré-requisitos
* PHP 8.0 ou superior
* MySQL/MariaDB
* Composer (Opcional, apenas se expandir bibliotecas)

### Passo a Passo

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/marcelocoi/coi-engenharia-platform.git](https://github.com/marcelocoi/coi-engenharia-platform.git)
    ```

2.  **Configure o Banco de Dados:**
    * Crie um banco de dados MySQL.
    * Importe o arquivo `database/schema.sql`.

3.  **Configuração de Ambiente:**
    * Renomeie `src/config/db_config.example.php` para `db_config.php`.
    * Edite o arquivo com suas credenciais locais.
    * Crie um arquivo `.env` na raiz (baseado no exemplo) e adicione sua `GEMINI_API_KEY`.

4.  **Execução:**
    * Configure seu servidor web (Apache/Nginx) para apontar para a pasta raiz.
    * Acesse `https://localhost/src/public_site` para o site público.
    * Acesse `https://localhost/src/intranet` para o sistema de gestão.

---

## 👤 Autor

**Eng. Marcelo de Barros** *Full Stack Developer & Engenheiro Civil*

Desenvolvedor sênior com foco em soluções tecnológicas para o setor de construção civil. Especialista em sistemas de alta performance e engenharia de dados.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/company/108664081/) 
[![Website](https://img.shields.io/badge/Website-0D2C54?style=for-the-badge&logo=google-chrome&logoColor=white)](https://coiengenharia.com.br)

---

<div align="center">
  <sub>Copyright © 2026 COI Engenharia. Distribuído sob a licença MIT.</sub>
</div>
