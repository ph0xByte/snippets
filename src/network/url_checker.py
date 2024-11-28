import requests
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from colorama import Fore, Style, init


init(autoreset=True)

underline = '\033[4m'
reset = '\033[0m'


class UrlChecker:
    def __init__(self, url) -> None:
        self.url = url
        self.hostname = url.split("//")[-1].split("/")[0]

    def check_http_methods(self) -> dict:
        """Prüft, welche HTTP-Methoden von der URL unterstützt werden."""
        Style.RESET_ALL
        http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"]
        results = {"allowed": [], "denied": []}

        print(f"\n{Fore.YELLOW + underline + Style.BRIGHT}Prüfung der unterstützten HTTP-Methoden für:{Style.RESET_ALL + '\t' + Fore.BLUE + underline}{self.url}{Style.RESET_ALL}")
        
        for method in http_methods:
            try:
                response = requests.request(method, self.url, timeout=10)
                if response.status_code < 400:
                    results["allowed"].append(method)
                else:
                    results["denied"].append((method, response.status_code))
            except requests.exceptions.RequestException as e:
                results["denied"].append((method, str(e)))

        # Ausgabe der Ergebnisse mit Colorama
        print(f"{Fore.CYAN}Erlaubte Methoden:{Style.RESET_ALL}")
        for method in results["allowed"]:
            print(f"{Fore.GREEN} * {method}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}Abgelehnte Methoden:{Style.RESET_ALL}")
        for method, reason in results["denied"]:
            print(f"{Fore.RED} * {method}: {reason}{Style.RESET_ALL}")
        print(90 * '-')
        
        return results

    def check_security_header(self) -> dict:
        """Prüft, ob die URL den HSTS-Header (Strict-Transport-Security) setzt."""
        Style.RESET_ALL
        try:
            response = requests.get(self.url, timeout=10)
            hsts_set    = 'Strict-Transport-Security' in response.headers
            csp_set     = 'Content-Security-Policy' in response.headers
            cross_orig  = 'Access-Control-Allow-Origin' in response.headers
            ref_policy  = 'Referrer-Policy' in response.headers

            print(f"\n{Fore.YELLOW + underline + Style.BRIGHT}Prüfung einiger Security-Header für:{Style.RESET_ALL + '\t' + Fore.BLUE + underline}{self.url}{Style.RESET_ALL}")
            if hsts_set:
                print(f"{Fore.GREEN}* HSTS-Header ist gesetzt.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}* HSTS-Header ist nicht gesetzt.{Style.RESET_ALL}")
            if csp_set:
                print(f"{Fore.GREEN}* CSP-Header ist gesetzt.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}* CSP-Header ist nicht gesetzt.{Style.RESET_ALL}")
            if cross_orig:
                print(f"{Fore.GREEN}* Cross-Origin-Header ist gesetzt.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}* Cross-Origin-Header ist nicht gesetzt.{Style.RESET_ALL}")
            if ref_policy:
                print(f"{Fore.GREEN}* Referrer-Policy-Header ist gesetzt.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}* Referrer-Policy-Header ist nicht gesetzt.{Style.RESET_ALL}")
            print(90 * '-')
            
            return {
                "reachable": True,
                "http_status": response.status_code,
                "hsts_set": hsts_set,
            }
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Fehler: Die URL ist nicht erreichbar. Grund: {e}{Style.RESET_ALL}")
            print(90 * '-')
            return {
                "reachable": False,
                "http_status": str(e),
                "hsts_set": False,
            }

    def print_all_headers(self) -> None: 
        print(f"\n{Fore.YELLOW + underline + Style.BRIGHT}Alle Header für:{Style.RESET_ALL + '\t' + Fore.BLUE + underline}{self.url}{Style.RESET_ALL}")

        try:
            response = requests.get(self.url, timeout=10)
            headers_dict = {key: value for key, value in response.headers.items()}
            max_length = max(len(key) for key in headers_dict.keys())
            for key, value in headers_dict.items():
                print(f'{Fore.GREEN}* {key.ljust(max_length)}{Style.RESET_ALL} : {Fore.BLUE}{value}{Style.RESET_ALL}')
            print(90 * '-')
        except requests.exceptions.ConnectionError as e:
             print(f"{Fore.RED}Fehler: Die URL ist nicht erreichbar. Grund: {e}{Style.RESET_ALL}")

    def get_certificate_info(self) -> dict|None:
        """Prüft das SSL-Zertifikat der URL und gibt Details zurück."""
        context = ssl.create_default_context()

        try:
            with socket.create_connection((self.hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    der_cert = ssock.getpeercert(True)
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    subject = {attr.oid._name: attr.value for attr in cert.subject}
                    issuer = {attr.oid._name: attr.value for attr in cert.issuer}
                    valid_from = cert.not_valid_before_utc  # Ohne Klammern verwenden
                    valid_to = cert.not_valid_after_utc    # Ohne Klammern verwenden
                    serial_number = cert.serial_number
                    signature_algorithm = cert.signature_algorithm_oid._name

                    return {
                        'subject': subject,
                        'issuer': issuer,
                        'valid_from': valid_from,
                        'valid_to': valid_to,
                        'serial_number': serial_number,
                        'signature_algorithm': signature_algorithm,
                    }
        except Exception as e:
            print(f"\n{Fore.RED}Fehler beim Abrufen des Zertifikats: {e}{Style.RESET_ALL}")
            print(90 * '-')
            return None

    def print_certificate_info(self) -> None:
        """Gibt die SSL-Zertifikatsinformationen aus."""
        cert_info = self.get_certificate_info()
        if not cert_info:
            return

        print(f"\n{Fore.YELLOW + underline + Style.BRIGHT}Zertifikatsinformationen für:{Style.RESET_ALL + '\t' + Fore.BLUE + underline}{self.url}{Style.RESET_ALL}")
        

        print(f"{Fore.CYAN}Subject:{Style.RESET_ALL}")
        for key, value in cert_info['subject'].items():
            print(f" * {key}: {value}")

        print(f"{Fore.CYAN}Issuer:{Style.RESET_ALL}")
        for key, value in cert_info['issuer'].items():
            print(f" * {key}: {value}")

        print(f"{Fore.CYAN}Gültigkeitszeitraum:{Style.RESET_ALL}")
        print(f" * Von : {cert_info['valid_from']}")
        print(f" * Bis : {cert_info['valid_to']}")

        print(f"{Fore.CYAN}Seriennummer: \n{Style.RESET_ALL} * {cert_info['serial_number']}")
        print(f"{Fore.CYAN}Signaturalgorithmus: \n{Style.RESET_ALL} * {cert_info['signature_algorithm']}")
        print(90 * '-')


if __name__ == "__main__":
    urls_to_check = [
       'https://www.example.com'
    ]
    
    url = urls_to_check[0]
   
    checker = UrlChecker(url)

    checker.check_http_methods()
    checker.check_security_header()
    checker.print_certificate_info()
    checker.print_all_headers()
