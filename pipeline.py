import os
import re
import json
import datetime
import requests
import boto3
from botocore.exceptions import ClientError

# ================= CONFIGURACIÓN =================
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/REMOVED" # Reemplaza con tu URL real
S3_ENDPOINT = "http://localhost:4566"
BUCKET_NAME = "ecommerce-app-bucket"

# ================= 1. ESCÁNER DE SECRETOS =================
def scan_secrets(directory="."):
    print("Iniciando escaneo de secretos...")
    # Patrón común para AWS Access Key ID (AKIA seguido de 16 caracteres alfanuméricos)
    aws_key_pattern = re.compile(r'AKIA[0-9A-Z]{16}')
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py") and file != "pipeline.py":
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if aws_key_pattern.search(content):
                        print(f"[!] ALERTA: Credencial de AWS encontrada en {filepath}")
                        return False
    print("[+] Escaneo de secretos aprobado.")
    return True

# ================= 2. VALIDACIÓN DE IaC (POLÍTICA S3) =================
def validate_iac(policy_file="policy.json"):
    print("Iniciando validación de IaC...")
    try:
        with open(policy_file, 'r') as f:
            policy = json.load(f)
            
        for statement in policy.get("Statement", []):
            if statement.get("Principal") == "*":
                print(f"[!] ALERTA: Política insegura detectada (Principal: '*') en {policy_file}. Acceso público habilitado.")
                return False
        print("[+] Validación de IaC aprobada.")
        return True
    except FileNotFoundError:
        print("No se encontró archivo policy.json, saltando validación.")
        return True

# ================= 3. NOTIFICACIONES Y AUDITORÍA =================
def send_slack_notification(status, message):
    if SLACK_WEBHOOK_URL == "TU_SLACK_WEBHOOK_URL":
        print("Slack webhook no configurado. Omitiendo notificación.")
        return

    color = "#36a64f" if status == "SUCCESS" else "#ff0000"
    payload = {
        "attachments": [{
            "color": color,
            "title": f"Resultado del Pipeline: {status}",
            "text": message
        }]
    }
    requests.post(SLACK_WEBHOOK_URL, json=payload)

def log_audit(user, secret_scan, iac_scan, deploy_status):
    date_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{date_now}] User: {user} | Secrets: {secret_scan} | IaC: {iac_scan} | Deploy: {deploy_status}\n"
    with open("audit_log.txt", "a") as f:
        f.write(log_entry)

# ================= 4. GATEKEEPER Y DESPLIEGUE =================
def deploy_to_localstack():
    print("Iniciando despliegue a LocalStack S3...")
    s3_client = boto3.client('s3', endpoint_url=S3_ENDPOINT, aws_access_key_id='test', aws_secret_access_key='test')
    try:
        s3_client.create_bucket(Bucket=BUCKET_NAME)
        s3_client.put_object(Bucket=BUCKET_NAME, Key='api_build.zip', Body=b'codigo_api_simulado')
        print("[+] Despliegue exitoso.")
        return True
    except ClientError as e:
        print(f"Error al conectar con LocalStack: {e}")
        return False

def main():
    user = os.getlogin()
    
    # Ejecutar controles
    secret_passed = scan_secrets()
    iac_passed = validate_iac()
    
    # Lógica del Gatekeeper
    if secret_passed and iac_passed:
        deploy_status = "SUCCESS" if deploy_to_localstack() else "FAILED_DEPLOY"
        message = "El código pasó todos los controles de seguridad y fue desplegado exitosamente."
    else:
        deploy_status = "BLOCKED"
        message = "Despliegue bloqueado. Se encontraron vulnerabilidades en el código o en la infraestructura."
        print("\n[GATEKEEPER] Pipeline detenido por fallos de seguridad.")
        
    # Auditoría y Notificación
    log_audit(user, "PASS" if secret_passed else "FAIL", "PASS" if iac_passed else "FAIL", deploy_status)
    send_slack_notification(deploy_status, message)

if __name__ == "__main__":
    main()