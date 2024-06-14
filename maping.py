import argparse, main.encabezados as encabezados, main.certificado as certificado

def main():
    parser = argparse.ArgumentParser(description="mAPIng es una herramienta de análisis de seguridad")
    parser.add_argument("-u", "--url", help="Especifica la URL a analizar")
    parser.add_argument("-e", "--encabezados", action="store_true", help="Muestra información de los encabezados de la URL")
    parser.add_argument("-c", "--certificado", action="store_true", help="Muestra información del certificado de la URL")

    args = parser.parse_args()

    if not args.url:
        print("Te damos la bienvenida a mAPIng! \n")
        print("Utiliza -u o --url seguido de la URL para analizar")
        print("Utiliza -h o --help para obtener ayuda \n")
        return

    if not (args.encabezados or args.certificado):
        args.encabezados = True
        args.certificado = True

    if args.encabezados:
        encabezados.analizar_encabezados(args.url)

    if args.certificado:
        certificado.analizar_certificado(args.url)

if __name__ == "__main__":
    print("\033[37m                    \033[32m_ _       _ _     _ _ _                               \033[0m")
    print("\033[37m    _ _   _ _     \033[32m_|_|_|_   _|_|_|_  |_|_|_|    \033[37m_ _       _ _     \033[0m")
    print("\033[37m  _|_|_|_|_|_|_  \033[32m|_|   |_| |_|   |_|   |_|    \033[37m_|_|_|_   _|_|_|_   \033[0m")
    print("\033[37m |_|   |_|   |_| \033[32m|_|_ _|_| |_|_ _|_|   |_|   \033[37m|_|   |_| |_|   |_|  \033[0m")
    print("\033[37m |_|   |_|   |_| \033[32m|_|   |_| |_|        _|_|_  \033[37m|_|   |_| |_|_ _|_|  \033[0m")
    print("\033[37m |_|   |_|   |_| \033[32m|_|   |_| |_|       |_|_|_| \033[37m|_|   |_|   |_|_|_|  \033[0m")
    print("\033[37m                                                         _ _ |_|                  \033[0m")
    print("\033[37m                                                        |_|_|_|                   \033[0m")
    print("\n                                        Creada por Vanessa Sastre")
    print("                                                 Versión 1.0 2024 \n")


    main()
