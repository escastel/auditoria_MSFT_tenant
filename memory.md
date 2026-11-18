#### 2. `MEMORIA.md`

# Memoria Técnica — Auditoría del Tenant con Microsoft Graph

## 1. Arquitectura y decisiones técnicas
El proyecto se ha estructurado en tres capas desacopladas para facilitar su mantenimiento y testeo:
- **`graph_client.py` (Capa de acceso a datos):** Gestiona la autenticación OAuth2, la paginación automática mediante `@odata.nextLink` y la captura controlada de errores HTTP `403` (`GraphPermissionError`).
- **`findings.py` (Capa de lógica de negocio):** Implementada mediante **funciones puras** que reciben estructuras de datos y devuelven hallazgos normalizados sin efectos secundarios ni llamadas de red.
- **`main.py` (Orquestación y salida):** Coordina las consultas, aplica degradación elegante (*graceful degradation*) si el tenant carece de licencia Entra ID P1, ordena los resultados por criticidad y exporta el informe a `informe_auditoria.json`.

**Principio de mínimo privilegio:** Se utilizan exclusivamente permisos `.Read.All` para garantizar que la herramienta opere en modo estricto de solo lectura sin capacidad de alterar usuarios, roles ni configuraciones.

**Autenticación:** Dado que el portal administrativo (`entra.microsoft.com`) requería el registro de un dispositivo MFA para el acceso inicial, se implementó soporte dual en `main.py`: permite ejecutar la auditoría tanto con credenciales de aplicación (`client_credentials`) como mediante un *Access Token* delegado obtenido desde Graph Explorer.

---

## 2. Criterios de severidad y acción del analista

| Severidad | Criterio aplicado | Acción recomendada al analista |
| :--- | :--- | :--- |
| **CRÍTICO** | **Administrador sin MFA:** Compromiso directo de una cuenta con capacidad de control total o parcial del tenant. | Bloquear sesiones activas inmediatamente, forzar el registro de MFA resistente a phishing y auditar registros de actividad recientes. |
| **ALTO** | **Exceso de Global Admins (>4)** o **usuario estándar sin MFA** / **admin inactivo (>90 días):** Amplía drásticamente la superficie de ataque. | Revocar el rol *Global Administrator* a usuarios que no lo requieran y migrar a roles granulares o Privileged Identity Management (PIM). |
| **MEDIO** | **Invitados externos activos** o **usuarios estándar inactivos (>90 días):** Cuentas potencialmente huérfanas o con acceso externo no revisado. | Revisar con el responsable del área si el colaborador externo sigue activo; deshabilitar cuentas sin uso. |
| **BAJO** | **Licencias contratadas sin asignar:** Impacto operativo/financiero sin brecha de seguridad inmediata. | Reasignar o reducir suscripciones de pago infrautilizadas en el centro de administración. |

---

## 3. Análisis de falsos positivos detectados en el tenant
Al ejecutar la herramienta contra el entorno proporcionado se observaron dos hallazgos que ilustran la importancia del contexto antes de escalar alertas:
1. **13 Global Admins (`alumno1`..`alumno30`):** En un entorno corporativo real sería una anomalía grave; sin embargo, al tratarse de un tenant compartido de evaluación técnica, responde a la necesidad de dar visibilidad a los candidatos.
2. **999.998 licencias `POWER_BI_STANDARD` sin asignar:** Microsoft aprovisiona por defecto un pool virtual de 1.000.000 de licencias gratuitas de Power BI Standard. Aunque la regla aritmética detecta unidades libres, no supone ningún sobrecoste económico real.

---

## 4. Privacidad y seguridad de la información
- **Protección de secretos:** Las credenciales y tokens se cargan mediante variables de entorno desde `.env`, excluido explícitamente del control de versiones mediante `.gitignore`.
- **Datos personales (PII):** El informe maneja identificadores (`userPrincipalName` y `id` de usuarios del directorio). Para compartir el informe fuera del equipo de seguridad o en entornos públicos, los UPN deben anonimizarse (por ejemplo, aplicando un hash SHA-256 truncado o enmascarando la parte local del correo).

---

## 5. Errores de la IA detectados y corregidos
Durante el desarrollo asistido por IA se identificaron y corrigieron los siguientes fallos:
1. **Asunción de licencia Entra ID P1 en endpoints de auditoría:** La propuesta inicial consultaba `/reports/authenticationMethods/userRegistrationDetails` y `signInActivity` asumiendo que siempre están disponibles. En tenants sin licencia P1, Graph responde con `403 Forbidden`, lo que abortaba la ejecución completa. Se corrigió encapsulando estas llamadas en bloques `try/except GraphPermissionError` para omitir dichos apartados con un aviso y completar el resto de la auditoría.
2. **Falta de paginación en las respuestas de Graph:** En una primera versión, las consultas leían únicamente `response.json()["value"]`. Microsoft Graph pagina resultados a partir de 100 elementos; sin recorrer `@odata.nextLink`, en tenants medianos o grandes se habrían omitido usuarios de forma silenciosa. Se implementó `get_all_pages()` para iterar hasta agotar todas las páginas.

---

## 6. Mejoras futuras (si hubiera más tiempo)
- **Batería de tests unitarios con `pytest`:** Aprovechar que `findings.py` está escrito con funciones puras para probar casos límite (0 Global Admins, admins sin MFA, invitados deshabilitados).
- **Filtrado de SKUs gratuitos:** Excluir de la alerta de licencias aquellas suscripciones gratuitas por defecto (`POWER_BI_STANDARD`, `FLOW_FREE`) para reducir el ruido operativo.
- **Roles asignados a grupos:** Ampliar la inspección de administradores para resolver miembros anidados dentro de grupos asignables a roles.