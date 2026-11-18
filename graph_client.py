import requests

class GraphPermissionError(Exception):
    """Excepción personalizada para errores de permisos o licencias en Microsoft Graph.

    Se lanza cuando la API devuelve un código de estado HTTP 403 (Forbidden),
    generalmente por falta de consentimiento en los permisos de la aplicación
    o porque el tenant carece de la licencia requerida (ej. Microsoft Entra ID P1).
    """
    pass

def get_all_pages(url: str, token: str) -> list[dict]:
    """Obtiene todos los registros de un endpoint de Microsoft Graph manejando la paginación.

    Realiza peticiones GET autenticadas y recorre automáticamente los enlaces de
    paginación (`@odata.nextLink`) hasta recopilar todos los elementos devueltos
    en la clave `"value"`.

    Args:
        url (str): URL inicial del endpoint de Microsoft Graph a consultar.
        token (str): Token de acceso OAuth2 (Bearer token) válido para la API.

    Returns:
        list[dict]: Lista consolidada con todos los objetos obtenidos a través de
            todas las páginas de resultados.

    Raises:
        GraphPermissionError: Si la API responde con un código HTTP 403 (acceso denegado).
        requests.exceptions.HTTPError: Si ocurre cualquier otro error HTTP (4xx o 5xx).
        requests.exceptions.RequestException: Si se produce un fallo de red o timeout.
    """
    headers = {"Authorization": f"Bearer {token}"}
    results = []
    next_url = url

    while next_url:
        response = requests.get(next_url, headers=headers, timeout=15)
        if response.status_code == 403:
            raise GraphPermissionError(f"Acceso denegado (403) en {url}: {response.text}")
        response.raise_for_status()
        data = response.json()
        results.extend(data.get("value", []))
        next_url = data.get("@odata.nextLink")

    return results