from datetime import datetime, timezone

GLOBAL_ADMIN_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

def analyze_administrators(roles: list[dict]) -> tuple[list[dict], set[str]]:
    """Evalúa la asignación de roles privilegiados y el número de Global Administrators.

    Recorre los roles activos del directorio para recopilar los identificadores de
    todos los usuarios con algún rol administrativo y verifica que la cantidad de
    administradores globales se mantenga dentro del rango recomendado (entre 2 y 4).

    Args:
        roles (list[dict]): Lista de roles de directorio con sus miembros expandidos
            procedentes del endpoint `/directoryRoles?$expand=members`.

    Returns:
        tuple[list[dict], set[str]]: Una tupla con dos elementos:
            - Lista de diccionarios con los hallazgos de seguridad detectados.
            - Conjunto (`set`) con los IDs únicos de los usuarios privilegiados.
    """
    findings = []
    privileged_user_ids = set()
    global_admins = []

    for role in roles:
        role_name = role.get("displayName", "Rol desconocido")
        members = role.get("members", [])
        for member in members:
            if member.get("@odata.type") == "#microsoft.graph.user":
                privileged_user_ids.add(member["id"])
                if role.get("roleTemplateId") == GLOBAL_ADMIN_TEMPLATE_ID:
                    global_admins.append(member.get("userPrincipalName"))

    if len(global_admins) > 4:
        findings.append({
            "categoria": "Administradores",
            "severidad": "ALTO",
            "detalle": f"Exceso de Global Admins ({len(global_admins)}): {', '.join(global_admins)}. Se recomienda entre 2 y 4."
        })
    elif len(global_admins) < 2:
        findings.append({
            "categoria": "Administradores",
            "severidad": "MEDIO",
            "detalle": f"Solo hay {len(global_admins)} Global Admin(s). Riesgo de bloqueo si se pierde acceso."
        })

    return findings, privileged_user_ids

def analyze_mfa(users: list[dict], mfa_details: list[dict], admin_ids: set[str]) -> list[dict]:
    """Detecta usuarios activos sin métodos de autenticación multifactor (MFA) registrados.

    Cruza el listado de cuentas habilitadas con el informe de registro de métodos de
    autenticación. Asigna severidad `CRÍTICO` si la cuenta sin MFA pertenece a un
    administrador y `ALTO` si se trata de un usuario estándar.

    Args:
        users (list[dict]): Lista de usuarios del directorio.
        mfa_details (list[dict]): Detalles de registro de MFA obtenidos de
            `/reports/authenticationMethods/userRegistrationDetails`.
        admin_ids (set[str]): Conjunto de IDs de usuarios con roles privilegiados.

    Returns:
        list[dict]: Lista de hallazgos correspondientes a cuentas activas sin MFA.
    """
    findings = []
    mfa_map = {item["id"]: item.get("isMfaRegistered", False) for item in mfa_details}

    for user in users:
        if not user.get("accountEnabled", True):
            continue
        uid = user["id"]
        if uid in mfa_map and not mfa_map[uid]:
            is_admin = uid in admin_ids
            findings.append({
                "categoria": "Sin MFA",
                "severidad": "CRÍTICO" if is_admin else "ALTO",
                "detalle": f"Usuario {'ADMINISTRADOR ' if is_admin else ''}{user.get('userPrincipalName')} activo sin MFA registrado."
            })
    return findings

def analyze_inactivity(users: list[dict], admin_ids: set[str], max_days: int = 90) -> list[dict]:
    """Identifica cuentas habilitadas que superan el umbral de días sin iniciar sesión.

    Evalúa la marca temporal `lastSignInDateTime` dentro de `signInActivity` para
    detectar cuentas potencialmente huérfanas o abandonadas, priorizando aquellas
    que disponen de privilegios administrativos.

    Args:
        users (list[dict]): Lista de usuarios del directorio con el campo `signInActivity`.
        admin_ids (set[str]): Conjunto de IDs de usuarios con roles privilegiados.
        max_days (int, optional): Número máximo de días de inactividad permitidos antes
            de generar un hallazgo. Por defecto es 90.

    Returns:
        list[dict]: Lista de hallazgos de inactividad clasificados por severidad.
    """
    findings = []
    now = datetime.now(timezone.utc)

    for user in users:
        if not user.get("accountEnabled", True):
            continue
        sign_in = user.get("signInActivity") or {}
        last_sign_in_str = sign_in.get("lastSignInDateTime")
        if not last_sign_in_str:
            continue

        last_dt = datetime.fromisoformat(last_sign_in_str.replace("Z", "+00:00"))
        days_inactive = (now - last_dt).days
        if days_inactive > max_days:
            is_admin = user["id"] in admin_ids
            findings.append({
                "categoria": "Inactividad",
                "severidad": "ALTO" if is_admin else "MEDIO",
                "detalle": f"{user.get('userPrincipalName')} lleva {days_inactive} días sin iniciar sesión."
            })
    return findings

def analyze_guests(users: list[dict]) -> list[dict]:
    """Audita las cuentas de usuarios invitados externos habilitadas en el tenant.

    Filtra los usuarios cuyo tipo sea `Guest` y se encuentren activos, reportando su
    fecha de último acceso para facilitar la revisión periódica de permisos externos.

    Args:
        users (list[dict]): Lista de usuarios del directorio.

    Returns:
        list[dict]: Lista de hallazgos asociados a cuentas invitadas activas.
    """
    findings = []
    for user in users:
        if user.get("userType") == "Guest" and user.get("accountEnabled", True):
            sign_in = (user.get("signInActivity") or {}).get("lastSignInDateTime", "Sin registro / N/A")
            findings.append({
                "categoria": "Invitados",
                "severidad": "MEDIO",
                "detalle": f"Cuenta invitada activa: {user.get('userPrincipalName')} (Último acceso: {sign_in})."
            })
    return findings

def analyze_licenses(skus: list[dict]) -> list[dict]:
    """Analiza el aprovechamiento de las licencias contratadas en el tenant.

    Compara el total de unidades habilitadas (`prepaidUnits.enabled`) frente a las
    unidades consumidas (`consumedUnits`) en cada suscripción para detectar licencias
    disponibles sin asignar.

    Args:
        skus (list[dict]): Lista de suscripciones obtenidas del endpoint `/subscribedSkus`.

    Returns:
        list[dict]: Lista de hallazgos informativos sobre licencias sin asignar.
    """
    findings = []
    for sku in skus:
        name = sku.get("skuPartNumber", "Desconocida")
        total = sku.get("prepaidUnits", {}).get("enabled", 0)
        used = sku.get("consumedUnits", 0)
        unused = total - used
        if unused > 0:
            findings.append({
                "categoria": "Licencias",
                "severidad": "BAJO",
                "detalle": f"Licencia {name}: {unused} sin asignar de {total} contratadas ({used} en uso)."
            })
    return findings