import requests

def obtener_encabezados(url):
    """
    Obtiene los encabezados de una URL dada.

    Args: url (str): La URL para la que se deben obtener los encabezados.

    Returns: dict or None: Un diccionario que contiene los encabezados de la respuesta si la solicitud es exitosa, None si falla.
    """
    try:
        response = requests.get(url)
        return response.headers
    except requests.exceptions.RequestException as e:
        return f"Error al obtener los encabezados: {e}"

def analizar_x_content_type_options(headers):
    """
    Analiza el encabezado X-Content-Type-Options.

    Args: headers (dict): Un diccionario que contiene los encabezados de la respuesta HTTP.
    """
    x_content_type_option_status = '✅' if 'X-Content-Type-Options' in headers else '❌'
    print(f"{x_content_type_option_status} Se envía el encabezado X-Content-Type-Options: nosniff \n")
    
    if x_content_type_option_status == '❌':
        print(f"\tEvidencia: No se encuentra el encabezado X-Content-Type-Options")
        print("\tRecomendación: Configura correctamente el encabezado Content-Type en todo el sitio.")
        print("\tEl encabezado X-Content-Type-Options: nosniff debería estar presente para prevenir ataques de confusión de MIME.")
        print("\tPuedes leer más información sobre esto aquí: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-content-type-options\033[0m \n")

def analizar_x_frame_options(headers):
    """
    Analiza el encabezado X-Frame-Options.

    Args: headers (dict): Un diccionario que contiene los encabezados de la respuesta HTTP.
    """
    if 'X-Frame-Options' in headers:
        x_frame_option_status = '✅'
        x_frame_option_value = headers['X-Frame-Options'].strip().lower()
        if x_frame_option_value == 'deny':
            print(f"{x_frame_option_status} Se encuentra el encabezado X-Frame-Options: deny \n")
        else:
            print(f"⚠️  Se encuentra el encabezado X-Frame-Options, pero su valor es: {x_frame_option_value} \n")
            print("\tRecomendación: Cambiar el valor del encabezado X-Frame-Options a 'deny' para mayor seguridad.")
            print("\tPuedes leer más información sobre esto aquí: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-frame-options\033[0m \n")

    else:
        x_frame_option_status = '❌'
        print(f"{x_frame_option_status} No se encuentra el encabezado X-Frame-Options: deny \n")
        print(f"\tEvidencia: No se encuentra el encabezado X-Frame-Options")
        print("\tRecomendación: No permitir la visualización de la página en un marco.")
        print("\tEl encabezado X-Frame-Options: deny debería estar presente para evitar ataques de clickjacking.")
        print("\tTen en cuenta que el encabezado X-Frame-Options es obsoleto para navegadores que admiten la directiva frame-ancestors de la Política de Seguridad de Contenido (CSP).")
        print("\tSi es posible, utiliza la directiva frame-ancestors de CSP en lugar de X-Frame-Options.")
        print("\tPuedes leer más información sobre esto aquí: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-frame-options\033[0m \n")

def analizar_content_security_policy(headers):
    """
    Analiza el encabezado Content-Security-Policy.

    Args:
        headers (dict): Un diccionario que contiene los encabezados de la respuesta HTTP.
    """
    csp_header_exists = any(header.lower().startswith('content-security-policy') for header in headers)
    content_security_policy_status = '✅' if csp_header_exists else '❌'
    
    print(f"{content_security_policy_status} Se envía el encabezado Content-Security-Policy.\n")
    
    if not csp_header_exists:
        print("\tEvidencia: No se encontró el encabezado Content-Security-Policy.")
        print("\tRecomendación: Configurar y mantener una Política de Seguridad de Contenido (CSP) es crucial.")
        print("\tLa CSP ayuda a detectar y mitigar ciertos tipos de ataques, como XSS y ataques de inyección de datos.")
        print("\tSin embargo, ten en cuenta que este encabezado puede no ser relevante en respuestas de una API REST que devuelva contenido que no se vaya a renderizar.")
        print("\tPuedes leer más información sobre esto aquí: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html#1-content-security-policy-header\033[0m\n")

def analizar_fingerprinting(headers):
    """
    Analiza los encabezados de fingerprinting.

    Args: headers (dict): Un diccionario que contiene los encabezados de la respuesta HTTP.
    """
    fingerprinting_headers = ['X-Powered-By', 'Server', 'X-AspNet-Version']
    fingerprinting_status = '✅' if all(header not in headers for header in fingerprinting_headers) else '❌'
    fingerprinting_evidence = [header for header in fingerprinting_headers if header in headers]
    print(f"{fingerprinting_status} No se encontraron encabezados de huella digital del servidor - X-Powered-By, Server, X-AspNet-Version. \n")
    if fingerprinting_status == '❌':
        print(f"\tEvidencia: Se encontraron los encabezados {', '.join(fingerprinting_evidence)}")
        print("\tRecomendación: Elimina o establece valores no informativos para estos encabezados.")
        print("\tLos encabezados de huella digital del servidor pueden exponer información sobre las tecnologías utilizadas, lo que facilita a los atacantes encontrar vulnerabilidades.")
        print("\tRecuerda que los atacantes tienen otros medios para identificar la tecnología de tu servidor.")
        print("\tPuedes leer más información sobre esto aquí: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-powered-by\033[0m \n")
        print("\t \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#server\033[0m \n")
        print("\t \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-aspnet-version\033[0m \n")

def analizar_content_type(headers):
    """
    Analiza el encabezado Content-Type.

    Args: headers (dict): Un diccionario que contiene los encabezados de la respuesta HTTP.
    """
    if 'Content-Type' in headers:
        content_type = headers['Content-Type'].strip().lower()
        if 'text/html' in content_type:
            print(f"✅ Correcto tipo de contenido para la respuesta: {content_type} \n")
        else:
            print(f"❌ Se encuentra el encabezado Content-Type, pero su valor es: {content_type} \n")
            print("\tRecomendación: Establece correctamente el encabezado Content-Type a 'text/html' si el contenido es HTML.")
            print("\tAunque se recomienda establecer siempre correctamente el encabezado Content-Type, solo constituiría una vulnerabilidad si el contenido está destinado a ser renderizado por el cliente y el recurso no es de confianza (proporcionado o modificado por un usuario).")
            print("\tRecuerda que el atributo charset es necesario para prevenir XSS en páginas HTML.")
            print("\tRecuerda también que el text/html puede ser cualquiera de los tipos MIME posibles.")
            print("\tPuedes leer más información sobre esto aquí: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#content-type\033[0m \n")
    else:
        print("❌ No se encuentra el encabezado Content-Type \n")
        print("\tEvidencia: No se encuentra el encabezado Content-Type")
        print("\tRecomendación: Asegúrate de establecer correctamente el encabezado Content-Type en la respuesta.")
        print("\tLa ausencia del encabezado Content-Type puede causar problemas en la interpretación del contenido por parte del cliente y potencialmente llevar a vulnerabilidades de seguridad.")
        print("\tRecuerda que el atributo charset es necesario para prevenir XSS en páginas HTML.")
        print("\tPuedes leer más información sobre esto aquí: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#content-type\033[0m \n")

def analizar_encabezados(url):
    """
    Analiza todos los encabezados de una URL dada.

    Args: url (str): La URL para la que se deben analizar los encabezados.
    """
    headers = obtener_encabezados(url)
    if headers:
        print("\n\033[1m-------------------------------------------------------------------------------------------\033[0m")
        print("\033[1m\n                    ANALISIS DE ENCABEZADOS:\033[0m \n")
        print("\033[1m-------------------------------------------------------------------------------------------\033[0m\n")
        
        analizar_x_content_type_options(headers)
        analizar_x_frame_options(headers)
        analizar_content_security_policy(headers)
        analizar_fingerprinting(headers)
        analizar_content_type(headers)
    else:
        print("No se pudo obtener los encabezados de la URL proporcionada.")
