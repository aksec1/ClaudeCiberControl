"""
Servidor con SSL directo (sin reverse proxy).
Útil para redes internas o cuando no se puede usar nginx.

Uso:
  - Con Let's Encrypt (win-acme genera los .pem):
      python run_https.py --cert cert.pem --key key.pem

  - Con certificado autofirmado (solo para pruebas internas):
      python run_https.py --selfsigned

Variables de entorno alternativas:
  SSL_CERT_FILE=C:/ruta/cert.pem
  SSL_KEY_FILE=C:/ruta/key.pem
"""
import os
import sys
import ssl
import argparse

sys.path.insert(0, os.path.dirname(__file__))


def generate_selfsigned(cert_path, key_path):
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime, ipaddress
    except ImportError:
        print("ERROR: Instala 'cryptography' para generar certificados autofirmados:")
        print("  pip install cryptography")
        sys.exit(1)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, os.getenv("COMPANY_NAME", "Mi Empresa")),
        x509.NameAttribute(NameOID.COMMON_NAME, "rendiciones.local"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    print(f"[OK] Certificado autofirmado generado: {cert_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", default=os.getenv("SSL_CERT_FILE", "ssl/cert.pem"))
    parser.add_argument("--key", default=os.getenv("SSL_KEY_FILE", "ssl/key.pem"))
    parser.add_argument("--selfsigned", action="store_true")
    parser.add_argument("--host", default=os.getenv("HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", 443)))
    args = parser.parse_args()

    if args.selfsigned:
        os.makedirs("ssl", exist_ok=True)
        generate_selfsigned(args.cert, args.key)

    if not os.path.exists(args.cert) or not os.path.exists(args.key):
        print(f"ERROR: No se encontraron los archivos de certificado.")
        print(f"  Cert: {args.cert}")
        print(f"  Key:  {args.key}")
        print("Usa --selfsigned para generar uno de prueba, o provee los paths correctos.")
        sys.exit(1)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(args.cert, args.key)

    from app import create_app
    from waitress import serve

    app = create_app()
    print(f"Servidor HTTPS en https://{args.host}:{args.port}")
    serve(app, host=args.host, port=args.port, threads=8, ssl_context=ctx)


if __name__ == "__main__":
    main()
