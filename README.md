# Auditoría de Seguridad de Tenant Microsoft Entra ID

Herramienta en Python de **solo lectura** que se conecta a Microsoft Graph API para auditar la postura de seguridad de un tenant de Microsoft 365 / Entra ID, clasificar hallazgos por severidad y exportar un informe en JSON.

## Estructura del repositorio
```text
.
├── main.py                  # Orquestador principal, resumen del tenant y exportación del informe
├── graph_client.py          # Cliente HTTP para Microsoft Graph (OAuth2, paginación y control de errores)
├── findings.py              # Funciones puras con las reglas de análisis y asignación de severidad
├── memory.md                # Memoria técnica: decisiones de diseño, criterios, falsos positivos y errores de IA corregidos
├── .env.example             # Plantilla de variables de entorno necesarias para la autenticación
├── informe_auditoria.json   # Ejemplo de salida generada con los avisos y hallazgos ordenados
└── README.md                # Guía de instalación, configuración y ejecución
```
## Requisitos previos

- Python 3.10 o superior
- Credenciales de acceso a Microsoft Graph con permisos de solo lectura:
    * `User.Read.All`
    * `Group.Read.All` 
    * `RoleManagement.Read.Directory`
    * `AuditLog.Read.All`
    * `Organization.Read.All`

## Instalación

1. Clona el repositorio y accede al directorio:
   ```bash
   git clone https://github.com/escastel/auditoria_MSFT_tenant.git
   cd auditoria
2. Crea un entorno virtual e instala las dependencias:
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # En Windows: .venv\Scripts\activate
    pip install requests python-dotenv
3. Configura las variables de entorno copiando el archivo ``` .env.example``` a ```.env```:
    ```bash
    cp .env.example .env
Rellena una de las dos opciones en .env:
* **Opción A (Token delegado desde Graph Explorer):** Pega el token en ```GRAPH_ACCESS_TOKEN```.
* **Opción B (Aplicación registrada en Entra ID):** Rellena ```TENANT_ID```, ```CLIENT_ID``` y ```CLIENT_SECRET```.

## Ejecucción 
```bash
python main.py
```
Al ejecutarse, el script mostrará por consola los avisos de licencia (por ejemplo, si el tenant no dispone de Entra ID P1), un resumen general del directorio y los hallazgos ordenados por criticidad (```CRÍTICO```, ```ALTO```, ```MEDIO```, ```BAJO```), guardando además el resultado completo en ```informe_auditoria.json```.

