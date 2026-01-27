<div align="center">

  <img src="src/public_site/LOGO.png" alt="COI Engenharia Logo" width="150" />

  # COI Engenharia - Plataforma de Gestão & Inteligência Corporativa
  
  **Sistema Integrado de Engenharia (RDO), Gestão Eletrônica de Documentos (GED) e Administração de Obras.**

  [![PHP Version](https://img.shields.io/badge/php-8.0%2B-777BB4?style=for-the-badge&logo=php&logoColor=white)](https://www.php.net/)
  [![Database](https://img.shields.io/badge/MySQL-00000F?style=for-the-badge&logo=mysql&logoColor=white)](https://www.mysql.com/)
  [![Frontend](https://img.shields.io/badge/HTML5%20%2F%20JS-E34F26?style=for-the-badge&logo=html5&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/Guide/HTML/HTML5)
  [![Security](https://img.shields.io/badge/Security-CSP%20%7C%20HSTS-success?style=for-the-badge&logo=security&logoColor=white)](#-cybersecurity--compliance)
  [![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

  [Sobre](#-contexto-e-propósito) • [Módulos](#-funcionalidades-e-módulos) • [Stack](#-%EF%B8%8F-arquitetura-e-stack) • [Segurança](#-cybersecurity--compliance) • [Instalação](#-instalação)

</div>

---

## 🏗️ Contexto e Propósito

Esta plataforma proprietária (ERP Técnico) foi desenvolvida sob medida para a **COI Engenharia** para centralizar a gestão operacional de obras de infraestrutura, terraplenagem e pavimentação. O sistema elimina o uso de papel no canteiro de obras, digitalizando processos críticos e garantindo rastreabilidade total.

O foco do desenvolvimento foi **Performance (Vanilla PHP)** e **Segurança (Defense in Depth)**, garantindo operabilidade mesmo em conexões instáveis de campo.

---

## 📸 Interface do Sistema

| **Dashboard Geral & Monitoramento** | **Gestão Eletrônica de Documentos (GED)** |
|:---:|:---:|
| <img src="assets/intranet.png" alt="Dashboard Intranet" width="100%"> | <img src="assets/1.png" alt="Gestão de Arquivos" width="100%"> |
| *Monitoramento de segurança e logs em tempo real* | *Interface Windows-like para gestão de arquivos* |

---

## ✨ Funcionalidades e Módulos

O sistema é dividido em módulos integrados com controle de acesso baseado em cargos (RBAC).

### 📋 1. RDO Digital (Relatório Diário de Obras)
Substituição completa dos diários de papel por um fluxo digital auditável.
* **Registro Climático:** Monitoramento manhã/tarde com condições de praticabilidade.
* **Gestão de Ativos:** Controle detalhado de efetivo (Mão de Obra) e Maquinário (Equipamentos) alocados.
* **Fluxo de Aprovação:** Sistema de validação em 3 níveis (Engenheiro, Fiscalização, Administração).
* **PDF Engine:** Geração automática de relatórios em PDF prontos para impressão/assinatura.
* **Evidências:** Galeria de fotos integrada com upload múltiplo e timestamps.
* **Histórico:** Log completo de edições e visualizações (quem viu, quem alterou).

### 📂 2. GED (Gestão Eletrônica de Documentos)
Um "Windows Explorer" web para gestão de acervo técnico.
* **Interface Intuitiva:** Navegação por pastas, breadcrumbs e ícones dinâmicos por tipo de arquivo.
* **Operações em Lote:** Upload via AJAX (Drag & Drop), exclusão em massa e **Download ZIP** on-the-fly.
* **Organização:** Criação de pastas e estruturação hierárquica de projetos.
* **Segurança:** Logs de upload, download e exclusão vinculados ao IP e Usuário.

### 📊 3. Dashboard & BI
Visualização estratégica para tomada de decisão.
* **KPIs de Obras:** Gráficos (Chart.js) de status de relatórios (Pendentes vs. Aprovados).
* **Matriz de Produtividade:** Visão geral de envios de RDOs por obra nos últimos 14 dias.
* **Auditoria de Segurança:** Monitoramento de tentativas de invasão, erros PHP e atividade de usuários em tempo real.

### 👥 4. Gestão de Acessos
* **Autenticação Híbrida:** Suporte a login local e integração via **IMAP/POP3** (Webmail Corporativo).
* **Controle de Usuários:** CRUD de usuários com vinculação específica a obras (O usuário vê apenas as obras permitidas).
* **Proteção:** Bloqueio temporário após tentativas falhas de login (Brute-force protection).

---

## 🛠️ Arquitetura e Stack

O projeto segue princípios de **Clean Code** sem dependência excessiva de frameworks pesados, priorizando velocidade.

| Componente | Tecnologia | Detalhes |
| :--- | :--- | :--- |
| **Backend** | **PHP 8.x (Vanilla)** | Arquitetura MVC própria, sem frameworks (Laravel/Symfony), garantindo baixa latência. |
| **Database** | **MySQL / MariaDB** | Uso de **PDO** com Prepared Statements para segurança total dos dados. |
| **Frontend** | **HTML5 / CSS3** | Design System próprio responsivo (Mobile-first) inspirado no Windows 11 e Dashboards modernos. |
| **JS Libs** | **Vanilla JS** | + Chart.js (Gráficos) e Feather Icons (Ícones leves). |
| **Server** | **Apache / Nginx** | Compatível com ambientes Linux e Windows Server. |

---

## 🔒 Cybersecurity & Compliance

A segurança implementa o conceito de **Defense in Depth** (Defesa em Profundidade), auditável via logs no banco de dados:

* **[CSP] Content Security Policy:** Headers rigorosos prevenindo XSS e injeção de scripts.
* **[Session Hardening]**: Cookies `HttpOnly`, `Secure`, `Strict` e regeneração de ID de sessão.
* **[Logs de Auditoria]**: Registro imutável de logins (sucesso/falha), uploads, downloads e edições de registros.
* **[Sanitização]**: Tratamento recursivo de inputs e uploads de arquivos (verificação de extensão/MIME).
* **[Anti-Bruteforce]**: Limitação de tentativas de login por sessão/IP.

---

## ⚙️ Instalação

### Pré-requisitos
* PHP 8.0+ (extensões: `pdo`, `mbstring`, `zip`, `gd`, `curl`).
* MySQL 5.7+ ou MariaDB.
* Servidor Web (Apache com `mod_rewrite` ativado).

### Passo a Passo

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/marcelocoi/coi-engenharia-platform.git](https://github.com/marcelocoi/coi-engenharia-platform.git)
    ```

2.  **Banco de Dados:**
    * Importe o script `database/schema.sql` para criar a estrutura inicial.
    * O sistema criará automaticamente um usuário `admin` padrão se a tabela estiver vazia na inicialização.

3.  **Configuração:**
    * Renomeie `src/config/db_config.example.php` para `db_config.php`.
    * Configure as credenciais do banco de dados e chave de API (se aplicável).

4.  **Permissões:**
    * Garanta permissão de escrita nas pastas:
      * `/src/intranet/data/logs/`
      * `/src/intranet/data/uploads/`
      * `/src/intranet/data/ged_repository/`

---

## 👤 Autor

**Eng. Marcelo de Barros** *CEO da COI Engenharia & Full Stack Developer por I.A*

Engenheiro Civil com expertise em grandes obras (Usina Nuclear Angra 3, Rodovias) e desenvolvimento de soluções tecnológicas para o setor de construção civil.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Conectar-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/company/108664081/) 
[![COI Engenharia](https://img.shields.io/badge/COI_Engenharia-Website_Oficial-0D2C54?style=for-the-badge&logo=google-chrome&logoColor=white)](https://coiengenharia.com.br)

---

<div align="center">
  <sub>Copyright © 2026 COI Engenharia. Todos os direitos reservados.</sub>
</div>
