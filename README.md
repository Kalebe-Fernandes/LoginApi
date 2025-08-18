
# 🔐 API de Autenticação de Usuários

Uma API RESTful moderna para gerenciamento de autenticação de usuários, construída com **.NET 9** e **C# 13**, seguindo os princípios da **Clean Architecture**. Desenvolvida para ser escalável, testável e segura.

---

## 🚀 Tecnologias Utilizadas

- ✅ **.NET 9** + **C# 13**
- 🗄️ **SQL Server** com **Entity Framework Core**
- 🔐 **JWT** para autenticação
- 🧱 **Clean Architecture**
- 🔄 **AutoMapper** para mapeamento de objetos
- 📏 **FluentValidation** para validação robusta de dados
- 📊 **Serilog** para logging estruturado
- 📌 **API Versioning**
- 🔧 Injeção de Dependência nativa

---

## 📁 Estrutura do Projeto

```plaintext
src/
├── AuthApi                -> Projeto principal da API (.NET 9)
├── AuthApi.Application    -> Casos de uso e regras de aplicação
├── AuthApi.Domain         -> Entidades de domínio e interfaces
├── AuthApi.Infrastructure -> Repositórios e serviços externos
├── AuthApi.Tests          -> Projeto de testes unitários/integrados
```

---

## 🧪 Funcionalidades

- ✅ Cadastro de usuários
- ✅ Login com geração de token JWT
- ✅ Logout e revogação de token (opcional)
- ✅ Atualização de senha
- ✅ Validações personalizadas com FluentValidation
- ✅ Controle de versão da API
- ✅ Log estruturado com Serilog

---

## ⚙️ Pré-requisitos

- [.NET 9 SDK](https://dotnet.microsoft.com/en-us/download)
- [SQL Server LocalDB ou SQL Server Express](https://learn.microsoft.com/sql/database-engine/configure-windows/sql-server-express-localdb)
- [Visual Studio 2022+](https://visualstudio.microsoft.com/) ou outro editor compatível

---

## 🛠️ Configuração e Execução

### 1️⃣ Clone o repositório

```bash
git clone https://github.com/seu-usuario/sua-api-auth.git
cd sua-api-auth
```

### 2️⃣ Configure o banco de dados

No arquivo `appsettings.Development.json` da pasta `AuthApi`, configure a string de conexão:

```json
"ConnectionStrings": {
  "DefaultConnection": "Server=localhost;Database=AuthDb;Trusted_Connection=True;TrustServerCertificate=True;"
}
```

### 3️⃣ Execute as migrações

```bash
dotnet ef database update --project ../AuthApi.Infrastructure --startup-project AuthApi
```

> Certifique-se de que a CLI do EF Core está instalada: `dotnet tool install --global dotnet-ef`

### 4️⃣ Rode a API

```bash
dotnet run --project AuthApi
```

A API será executada em: `https://localhost:5001`

---

## 🧪 Testando a API

Acesse o Swagger em:

```
https://localhost:5001/swagger
```

### Endpoints Principais

- `POST /api/v1/auth/register` → Registro de novo usuário
- `POST /api/v1/auth/login` → Login com e-mail e senha
- `GET /api/v1/users/me` → Dados do usuário logado (JWT necessário)

---

## 🧰 Injeção de Dependência

O projeto usa o **container nativo do .NET** para registrar e injetar:

- Serviços de aplicação
- Repositórios
- AutoMapper
- Validators (FluentValidation)
- Serilog
- JWT TokenService

---

## 📄 Logs com Serilog

Os logs estruturados são armazenados no console e/ou em arquivos. No `Program.cs`:

```csharp
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("Logs/log-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();
```

---

## 📚 Padrões e Boas Práticas

- Clean Architecture
- SOLID principles
- Validação na camada de Application
- Mapeamento DTO ↔️ Entidade
- JWT com políticas de autorização
- Logging e tratamento de exceções global

---

## 🧪 Rodando os Testes

```bash
dotnet test
```

---

## 📦 Pacotes Importantes

| Pacote | Descrição |
|--------|-----------|
| `Microsoft.EntityFrameworkCore.SqlServer` | Acesso ao SQL Server via EF Core |
| `FluentValidation.AspNetCore` | Validação fluente |
| `AutoMapper.Extensions.Microsoft.DependencyInjection` | Mapeamento de objetos |
| `Serilog.AspNetCore` | Logging estruturado |
| `Microsoft.AspNetCore.Authentication.JwtBearer` | Autenticação JWT |
| `Microsoft.AspNetCore.Mvc.Versioning` | Versionamento de API |

---

## 📃 Licença

Este projeto está licenciado sob a [MIT License](LICENSE).

---

## 🤝 Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou pull requests.

---

## 📬 Contato

Desenvolvido por **Kalebe Fernandes**  
📧 kallebe.fernandes@hotmail.com  
📦 GitHub: [@Kalebe-Fernandes](https://github.com/Kalebe-Fernandes?tab=repositories)

