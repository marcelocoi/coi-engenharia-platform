===========================================================
RELATÓRIO TÉCNICO - COI ENGENHARIA
Data: 27/01/2026
===========================================================

1. ARQUITETURA E STACK
----------------------
* Backend:    PHP 8.0+ (Vanilla/Puro) - Alta performance sem frameworks.
* Frontend:   HTML5, CSS3 (Design System Próprio), JS ES6+.
* Database:   MySQL / MariaDB (Driver PDO Seguro).
* Servidor:   Apache/Nginx (Compatível).

2. INTELIGÊNCIA ARTIFICIAL (Implementada)
-----------------------------------------
* Engine:     Google Gemini 2.0 Flash.
* Integração: Via REST API direta (cURL) sem dependências externas.
* Funções:    Chatbot corporativo contextualizado com dados da empresa.
* Prompting:  System Prompt com engenharia de contexto para obras industriais.

3. SEGURANÇA E COMPLIANCE (Defense in Depth)
--------------------------------------------
O sistema implementa múltiplas camadas de segurança nativa:

* [CSP] Content Security Policy:
  - Política rigorosa definindo origens permitidas (self, google, etc).
  - Uso de 'nonces' criptográficos para scripts inline.

* [HSTS] HTTP Strict Transport Security:
  - Força conexão HTTPS e protege contra Downgrade Attacks.

* [Proteção de Sessão]:
  - Cookies HttpOnly e Secure.
  - Proteção contra Session Fixation (regeneração de ID).
  - Anti-CSRF (Cross-Site Request Forgery) via tokens dinâmicos.

* [Anti-Automação]:
  - Rate Limiting baseado em IP (Prevenção de DDoS/Brute-force).
  - Honeypot em formulários (Captura de bots sem CAPTCHA intrusivo).

* [Sanitização]:
  - Inputs filtrados recursivamente.
  - SQL Injection prevenido via Prepared Statements (PDO).

4. MÓDULOS DO SISTEMA
---------------------
* INTRANET: Autenticação híbrida (Local + Webmail Fallback).
* GED: Gestão Eletrônica de Documentos (Upload, Download, Zip, Bulk Actions).
* RDO: Relatório Diário de Obras (Clima, Efetivo, Maquinário, Fotos).
* OBRAS: Gestão de portfólio e indicadores de avanço físico.

5. ESTRUTURA DE DIRETÓRIOS (Clean Architecture)
-----------------------------------------------
* /src/public_site ... Interface pública (Landing Page).
* /src/intranet ...... Aplicação restrita (Business Logic).
* /src/config ........ Credenciais isoladas (Fora do Webroot).
* /database .......... Schemas e Migrations.

===========================================================
Gerado automaticamente pelo Assistente de Engenharia.
