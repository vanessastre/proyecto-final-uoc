<p>
  <img src="main\resources\maping_logo.png" alt="mAPIng Logo">
</p>

mAPIng es una herramienta por línea de comandos (CLI) diseñada para evaluar la seguridad de aplicaciones web. 

Su interfaz permite a los usuarios solicitar análisis completos o específicos mediante banderas. 

Se enfoca en dos áreas principales de chequeo: encabezados (headers) y certificados de seguridad en la capa de transporte.

## Características Principales

- Análisis de encabezados HTTP, incluyendo X-Content-Type-Options, X-Frame-Options, Content-Security-Policy y Content-Type.
- Evaluación de certificados SSL/TLS, verificando la fuerza de la clave, el algoritmo de hashing, la emisión de certificados de comodín y la validez de Let’s Encrypt.


## Instalación

1. Clona este repositorio en tu máquina local.
2. Asegúrate de tener Python 3 instalado en tu sistema.
3. Instala las dependencias utilizando pip:

```
pip install -r requirements.txt
```

## Uso

```
python maping.py -u <URL> [-e] [-c]
```

- `-u, --url`: Especifica la URL que deseas analizar.
- `-e, --encabezados`: Muestra información detallada sobre las cabeceras HTTP de la URL (opcional).
- `-c, --certificado`: Muestra información detallada sobre el certificado SSL de la URL (opcional).

### Ejemplo de uso

Por defecto se ejecutan ambos análisis de encabezados y certificado. Si deseas ejecutar solo uno de ellos, puedes usar la bandera correspondiente.

Ejemplo de uso para ejecutar análisis de encabezados y certificado:

```
python maping.py -u https://example.com
```

Ejemplo de uso para ejecutar solo el análisis de encabezados:

```
python maping.py -u https://example.com -e
```

Ejemplo de uso para ejecutar solo el análisis de certificado:

```
python maping.py -u https://example.com -c
```

## Créditos

Creado por Vanessa Sastre.

## Licencia

Este proyecto está bajo la licencia [Reconocimiento-NoComercial-CompartirIgual 3.0 España de Creative Commons](LICENSE).
