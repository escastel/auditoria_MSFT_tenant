import os
import json
from dotenv import load_dotenv
from graph_client import get_all_pages, GraphPermissionError
from findings import (
    analyze_administrators,
    analyze_mfa,
    analyze_inactivity,
    analyze_guests,
    analyze_licenses,
)

def main():
    load_dotenv()
    token = os.environ["GRAPH_ACCESS_TOKEN"]

    warnings = []
    has_p1_signin = True

    try:
        users = get_all_pages(
            "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,userType,accountEnabled,signInActivity",
            token,
        )
    except GraphPermissionError:
        has_p1_signin = False
        warnings.append("Apartado 'Inactividad' omitido: el tenant no dispone de licencia Entra ID P1 para leer signInActivity.")
        users = get_all_pages(
            "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,userType,accountEnabled",
            token,
        )

    roles = get_all_pages("https://graph.microsoft.com/v1.0/directoryRoles?$expand=members", token)

    mfa_details = []
    try:
        mfa_details = get_all_pages(
            "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails",
            token,
        )
    except GraphPermissionError:
        warnings.append("Apartado 'MFA' omitido: el informe de métodos de autenticación requiere Entra ID P1.")

    skus = get_all_pages("https://graph.microsoft.com/v1.0/subscribedSkus", token)

    all_findings = []
    admin_findings, admin_ids = analyze_administrators(roles)
    all_findings.extend(admin_findings)

    if mfa_details:
        all_findings.extend(analyze_mfa(users, mfa_details, admin_ids))
    if has_p1_signin:
        all_findings.extend(analyze_inactivity(users, admin_ids, max_days=90))

    all_findings.extend(analyze_guests(users))
    all_findings.extend(analyze_licenses(skus))

    order = {"CRÍTICO": 0, "ALTO": 1, "MEDIO": 2, "BAJO": 3}
    all_findings.sort(key=lambda x: order.get(x["severidad"], 99))

    print(f"=== AUDITORÍA DEL TENANT ({len(users)} usuarios analizados) ===\n")
    
    total_guests = sum(1 for u in users if u.get("userType") == "Guest")
    total_disabled = sum(1 for u in users if not u.get("accountEnabled", True))
    print(f"Resumen: {len(users)} usuarios totales | {total_guests} invitados | {total_disabled} deshabilitados | {len(roles)} roles activos\n")
    
    for w in warnings:
        print(f"[AVISO] {w}\n")

    for f in all_findings:
        print(f"[{f['severidad']}] ({f['categoria']}) {f['detalle']}")

    with open("informe_auditoria.json", "w", encoding="utf-8") as file:
        json.dump({"avisos": warnings, "hallazgos": all_findings}, file, indent=2, ensure_ascii=False)
    print("\nInforme exportado a informe_auditoria.json")

if __name__ == "__main__":
    main()