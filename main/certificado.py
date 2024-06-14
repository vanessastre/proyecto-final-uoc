import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def obtener_certificado(url):
    """
    Obtiene el certificado SSL de una URL dada.

    Args: url (str): La URL para la que se debe obtener el certificado SSL.

    Returns: dict: Un diccionario que contiene los detalles del certificado SSL.
    """
    hostname = url.split("//")[-1].split("/")[0]
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except socket.gaierror as e:
        print(f"Error al resolver el nombre del host: {e}")
    except socket.error as e:
        print(f"Error al conectar con el servidor: {e}")
    except Exception as e:
        print(f"Error inesperado: {e}")
    return None

        
def obtener_certificado_pem(url):
    """
    Obtiene el certificado SSL en formato PEM de una URL dada.

    Args: url (str): La URL para la que se debe obtener el certificado SSL.

    Returns: bytes: El certificado SSL en formato PEM.
    """
    hostname = url.split("//")[-1].split("/")[0]
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_pem = ssl.DER_cert_to_PEM_cert(ssock.getpeercert(True))
            return cert_pem.encode('utf-8')

def obtener_common_name(cert):
    """
    Obtiene el nombre común (commonName) del certificado SSL.

    Args: cert (dict): Un diccionario que contiene los detalles del certificado SSL.

    Returns: str: El nombre común (commonName) del certificado SSL.
    """
    common_name = ""
    subject = cert.get("subject", [])
    if isinstance(subject, dict):
        common_name = subject.get("commonName", "")
    elif isinstance(subject, list):
        for k, v in subject:
            if k == "commonName":
                common_name = v

    return common_name

def obtener_tamano_clave(url):
    """
    Obtiene y devuelve el tamaño de la clave del certificado SSL de una URL dada.

    Args: url (str): La URL para la que se debe obtener el certificado SSL.

    Returns: int: El tamaño de la clave del certificado SSL.
    """
    cert_pem = obtener_certificado_pem(url)
    cert_bytes = x509.load_pem_x509_certificate(cert_pem, default_backend())
    tamano_clave_bits = cert_bytes.public_key().key_size
    return tamano_clave_bits

def analizar_fortaleza_clave(url):
    """
    Analiza la fortaleza de la clave del certificado SSL.

    Args: cert (dict): Un diccionario que contiene los detalles del certificado SSL.
    """
    key_size = obtener_tamano_clave(url)
    key_size_status = '✅' if key_size >= 2048 else '❌'
    print(f"{key_size_status} Fortaleza de la clave {'suficiente:' if key_size_status == '✅' else 'insuficiente:'} {key_size}\n")

    if key_size_status == '❌':
        print(f"\tEvidencia: Tamaño de la clave ({key_size} bits)")
        print("\tRecomendación: Utiliza una clave privada de al menos 2048 bits para garantizar la seguridad de la comunicación en línea.")
        print("\tPuedes encontrar más información aquí: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html#use-strong-keys-and-protect-them\033[0m\n")

def analizar_algoritmo_hash(url):
    """
    Analiza el algoritmo de hash utilizado en el certificado SSL.

    Args:
        url (str): La URL para la que se debe analizar el certificado SSL.
    """
    cert_pem = obtener_certificado_pem(url)
    cert_obj = x509.load_pem_x509_certificate(cert_pem, default_backend())
    signature_algorithm = cert_obj.signature_algorithm_oid._name
    if "sha256" in signature_algorithm.lower():
        print("✅ Algoritmo de hash criptográfico: SHA-256\n")
    else:
        print("❌ Algoritmo de hash criptográfico no es SHA-256")
        print("\tEvidencia: Algoritmo de hash utilizado:", signature_algorithm)
        print("\tRecomendación: Utiliza el algoritmo SHA-256 para el hashing en lugar de los algoritmos más antiguos MD5 y SHA-1.")
        print("\tPuedes encontrar más información aquí: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html#use-strong-cryptographic-hashing-algorithms\033[0m\n")

def analizar_nombres_dominio(url, cert):
    """
    Analiza los nombres de dominio del certificado SSL.

    Args: url (str): La URL para la que se obtuvo el certificado SSL.
             cert (dict): Un diccionario que contiene los detalles del certificado SSL.
    """
    hostname = url.split("//")[-1].split("/")[0]
    san_list = []
    subject_alt_names = cert.get('subjectAltName', [])
    for entry in subject_alt_names:
        if entry[0].lower() == 'dns':
            san_list.append(entry[1])
    common_name = obtener_common_name(cert)
    if hostname == common_name or hostname in san_list:
        print("✅ Nombres de dominio: Coinciden con el certificado \n")
    else:
        print("❌ Nombres de dominio: No coinciden con el certificado")
        print("\tEvidencia: El nombre de dominio del certificado no coincide con el nombre de dominio del servidor.")
        print("\tRecomendación: Asegúrate de que el nombre de dominio (o sujeto) del certificado coincida con el nombre de dominio completamente calificado del servidor que presenta el certificado.")
        print("\tPuedes encontrar más información aquí: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html#use-correct-domain-names\033[0m\n")

def analizar_certificado_comodin(cert):
    """
    Analiza si el certificado SSL es un certificado comodín.

    Args: cert (dict): Un diccionario que contiene los detalles del certificado SSL.
    """
    common_name = obtener_common_name(cert)
    if common_name.startswith("*."):
        print("❌ Certificado comodín: Evita el uso de certificados comodín")
        print("\tEvidencia: El certificado tiene un nombre de dominio comodín, lo que puede violar el principio de privilegio mínimo.")
        print("\tRecomendación: Utiliza certificados comodín solo donde haya una necesidad genuina en lugar de por conveniencia.")
        print("\tPuedes encontrar más información aquí: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html#carefully-consider-the-use-of-wildcard-certificates\033[0m\n")
    else:
        print("✅ Certificado comodín: No es un certificado comodín \n")

def analizar_autoridad_certificadora(cert):
    """
    Analiza la autoridad certificadora del certificado SSL.

    Args: cert (dict): Un diccionario que contiene los detalles del certificado SSL.
    """
    organization_name = ""
    issuer = cert.get("issuer", [])
    for item in issuer:
        for sub_item in item:
            if sub_item[0] == 'organizationName':
                organization_name = sub_item[1]
    if "Let's Encrypt" in organization_name:
        print("✅ Autoridad de Certificación (CA): Emitido por Let's Encrypt \n")
    else:
        print("❌ Autoridad de Certificación (CA): No emitido por Let's Encrypt")
        print("\tEvidencia: El certificado no está firmado por Let's Encrypt, que es una CA conocida y confiable.")
        print("\tRecomendación: Utiliza una CA confiable, como Let's Encrypt, para que los certificados sean automáticamente confiables para los usuarios.")
        print("\tPuedes encontrar más información aquí: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html#use-an-appropriate-certification-authority-for-the-applications-user-base\033[0m\n")
        
def analizar_certificado(url):
    """
    Analiza el certificado SSL de una URL dada.

    Args: url (str): La URL para la que se debe analizar el certificado SSL.
    """
    cert = obtener_certificado(url)
    if cert:
        print("\n\033[1m-------------------------------------------------------------------------------------------\033[0m")
        print("\033[1m\n                    ANALISIS DE CERTIFICADO:\033[0m \n")
        print("\033[1m-------------------------------------------------------------------------------------------\033[0m\n")
        
        analizar_fortaleza_clave(url)
        analizar_algoritmo_hash(url)
        analizar_nombres_dominio(url, cert)
        analizar_certificado_comodin(cert)
        analizar_autoridad_certificadora(cert)

    else:
        print("No se pudo obtener el certificado SSL de la URL proporcionada.")
