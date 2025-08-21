# 🔐 AuthAPI

![.NET](https://img.shields.io/badge/.NET-9.0-purple)
![License](https://img.shields.io/badge/License-MIT-green)
![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen)
![Coverage](https://img.shields.io/badge/Coverage-95%25-brightgreen)
![Version](https://img.shields.io/badge/Version-1.0.0-blue)

## 📝 Descrição

AuthAPI é uma API REST robusta e segura desenvolvida em .NET 9.0, projetada para gerenciar autenticação e autorização de usuários. Implementada seguindo os princípios da Clean Architecture, oferece endpoints seguros para registro, login, recuperação de senha e gerenciamento de tokens de acesso.

## 📚 Índice (Table of Contents)

- [🔐 AuthAPI](#-authapi)
  - [📝 Descrição](#-descrição)
  - [📚 Índice (Table of Contents)](#-índice-table-of-contents)
  - [✨ Principais Funcionalidades](#-principais-funcionalidades)
  - [🛠️ Tecnologias Utilizadas](#️-tecnologias-utilizadas)
  - [🌐 Endpoints da API](#-endpoints-da-api)
  - [🚀 Como Começar](#-como-começar)
    - [📋 Pré-requisitos](#-pré-requisitos)
    - [🔧 Instalação](#-instalação)
    - [⚙️ Configuração do Ambiente](#️-configuração-do-ambiente)
  - [💡 Exemplos de Uso](#-exemplos-de-uso)
    - [Exemplo com cURL](#exemplo-com-curl)
    - [Exemplo com JavaScript (fetch)](#exemplo-com-javascript-fetch)
  - [👨‍💻 Autor](#-autor)
  - [📄 Licença](#-licença)

## ✨ Principais Funcionalidades

- 🔐 **Autenticação JWT**: Sistema seguro de autenticação baseado em tokens JWT
- 👤 **Gerenciamento de Usuários**: Registro, login e gerenciamento de perfis de usuário
- 🔄 **Refresh Tokens**: Sistema de renovação automática de tokens
- 📧 **Confirmação de Email**: Verificação de email para novos usuários
- 🔑 **Recuperação de Senha**: Sistema seguro de reset de senha
- 🛡️ **Validação Robusta**: Validação de dados de entrada usando FluentValidation
- 📊 **Logging Estruturado**: Sistema de logs detalhado para monitoramento
- 🧪 **Testes Automatizados**: Cobertura completa de testes unitários e de integração

## 🛠️ Tecnologias Utilizadas

| Categoria | Tecnologia |
|-----------|------------|
| **Framework** | .NET 9.0 |
| **ORM** | Entity Framework Core |
| **Banco de Dados** | SQL Server |
| **Autenticação** | JWT Bearer Tokens |
| **Validação** | FluentValidation |
| **Mapeamento** | AutoMapper |
| **Testes** | xUnit, Moq, FluentAssertions |
| **Documentação** | Swagger/OpenAPI |
| **Containerização** | Docker |

## 🌐 Endpoints da API

| Método | Endpoint | Descrição | Autenticação |
|--------|----------|-----------|--------------|
| `POST` | `/api/auth/register` | Registrar novo usuário | ❌ |
| `POST` | `/api/auth/login` | Realizar login | ❌ |
| `POST` | `/api/auth/refresh` | Renovar token de acesso | ❌ |
| `POST` | `/api/auth/confirm-email` | Confirmar email do usuário | ❌ |
| `POST` | `/api/auth/forgot-password` | Solicitar reset de senha | ❌ |
| `POST` | `/api/auth/reset-password` | Redefinir senha | ❌ |
| `GET` | `/api/auth/profile` | Obter perfil do usuário | ✅ |
| `PUT` | `/api/auth/profile` | Atualizar perfil do usuário | ✅ |

### 📝 Exemplos de Requisições e Respostas

#### Registro de Usuário
**Requisição:**
```json
{
  "firstName": "João",
  "lastName": "Silva",
  "email": "joao.silva@email.com",
  "password": "MinhaSenh@123",
  "confirmPassword": "MinhaSenh@123"
}
```

**Resposta (201 Created):**
```json
{
  "success": true,
  "message": "Usuário registrado com sucesso. Verifique seu email para confirmar a conta.",
  "data": {
    "userId": "123e4567-e89b-12d3-a456-426614174000",
    "email": "joao.silva@email.com",
    "firstName": "João",
    "lastName": "Silva"
  }
}
```

#### Login
**Requisição:**
```json
{
  "email": "joao.silva@email.com",
  "password": "MinhaSenh@123"
}
```

**Resposta (200 OK):**
```json
{
  "success": true,
  "message": "Login realizado com sucesso.",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "def50200...",
    "tokenType": "Bearer",
    "expiresIn": 3600,
    "user": {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "email": "joao.silva@email.com",
      "firstName": "João",
      "lastName": "Silva"
    }
  }
}
```

## 🚀 Como Começar

### 📋 Pré-requisitos

- .NET 9.0 SDK ou superior
- SQL Server (LocalDB para desenvolvimento)
- Visual Studio 2022 ou Visual Studio Code
- Git

### 🔧 Instalação

1. **Clone o repositório:**
   ```bash
   git clone https://github.com/seuusuario/authapi.git
   cd authapi
   ```

2. **Restaure as dependências:**
   ```bash
   dotnet restore
   ```

3. **Configure o banco de dados:**
   ```bash
   dotnet ef database update --project src/AuthAPI.Infrastructure
   ```

4. **Execute a aplicação:**
   ```bash
   dotnet run --project src/AuthAPI.API
   ```

5. **Acesse a documentação:**
   - API: https://localhost:7001
   - Swagger UI: https://localhost:7001/swagger

### ⚙️ Configuração do Ambiente

Crie um arquivo `.env` na raiz do projeto com as seguintes variáveis:

```env
# Configurações do Banco de Dados
CONNECTION_STRING=Server=(localdb)\\mssqllocaldb;Database=AuthApiDb;Trusted_Connection=true;MultipleActiveResultSets=true

# Configurações JWT
JWT_SECRET=seu-jwt-secret-super-seguro-aqui-com-32-caracteres-ou-mais
JWT_ISSUER=AuthAPI
JWT_AUDIENCE=AuthAPI-Users
JWT_EXPIRES_IN_MINUTES=60

# Configurações de Email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=seu-email@gmail.com
SMTP_PASSWORD=sua-senha-de-app
SMTP_FROM_NAME=AuthAPI
SMTP_FROM_EMAIL=noreply@authapi.com

# Configurações da Aplicação
ENVIRONMENT=Development
API_URL=https://localhost:7001
FRONTEND_URL=https://localhost:3000
```

## 💡 Exemplos de Uso

### Exemplo com cURL

**Registro de usuário:**
```bash
curl -X POST https://localhost:7001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "firstName": "Maria",
    "lastName": "Santos",
    "email": "maria.santos@email.com",
    "password": "MinhaSenh@123",
    "confirmPassword": "MinhaSenh@123"
  }'
```

**Login:**
```bash
curl -X POST https://localhost:7001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "maria.santos@email.com",
    "password": "MinhaSenh@123"
  }'
```

**Obter perfil (com autenticação):**
```bash
curl -X GET https://localhost:7001/api/auth/profile \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Exemplo com JavaScript (fetch)

**Registro de usuário:**
```javascript
const registerUser = async (userData) => {
  try {
    const response = await fetch('https://localhost:7001/api/auth/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(userData)
    });

    const result = await response.json();
    
    if (result.success) {
      console.log('Usuário registrado:', result.data);
    } else {
      console.error('Erro no registro:', result.message);
    }
  } catch (error) {
    console.error('Erro na requisição:', error);
  }
};

// Exemplo de uso
registerUser({
  firstName: 'Carlos',
  lastName: 'Oliveira',
  email: 'carlos.oliveira@email.com',
  password: 'MinhaSenh@123',
  confirmPassword: 'MinhaSenh@123'
});
```

**Login e armazenamento do token:**
```javascript
const loginUser = async (email, password) => {
  try {
    const response = await fetch('https://localhost:7001/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password })
    });

    const result = await response.json();
    
    if (result.success) {
      // Armazenar tokens no localStorage
      localStorage.setItem('accessToken', result.data.accessToken);
      localStorage.setItem('refreshToken', result.data.refreshToken);
      
      console.log('Login realizado:', result.data.user);
      return result.data;
    } else {
      console.error('Erro no login:', result.message);
    }
  } catch (error) {
    console.error('Erro na requisição:', error);
  }
};
```

**Requisição autenticada:**
```javascript
const getUserProfile = async () => {
  try {
    const token = localStorage.getItem('accessToken');
    
    const response = await fetch('https://localhost:7001/api/auth/profile', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      }
    });

    const result = await response.json();
    
    if (result.success) {
      console.log('Perfil do usuário:', result.data);
      return result.data;
    }
  } catch (error) {
    console.error('Erro ao obter perfil:', error);
  }
};
```

## 👨‍💻 Autor e 📬 Contato

Desenvolvido por **Kalebe Fernandes**  
📧 kallebe.fernandes@hotmail.com  
📦 GitHub: [@Kalebe-Fernandes](https://github.com/Kalebe-Fernandes?tab=repositories)
- LinkedIn: [linkedin.com/in/kalebe-fernandes](https://www.linkedin.com/in/kalebe-fernandes-012a371ba/)

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

⭐ **Se este projeto te ajudou, considere dar uma estrela no repositório!**
