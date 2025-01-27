import socket
import requests
from colorama import Fore, Style
from bs4 import BeautifulSoup
import urllib3

# Sertifika doğrulama uyarısını devre dışı bırak
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def domain_to_ip(domain):
    """
    Domain adresini IP adresine çevirir.
    """
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return None

def siteyi_tara(url):
    """
    Verilen URL'yi tarar ve güvenlik açıklarını tespit eder.
    """
    try:
        print(Fore.BLUE + f"[INFO] {url} taranıyor..." + Style.RESET_ALL)
        # Sertifika doğrulama yapılmadan bağlantı kuruluyor
        response = requests.get(url, timeout=10, verify=False)  # Sertifika doğrulaması yapılmaz
        print(Fore.GREEN + f"[SUCCESS] {url} başarıyla erişildi!" + Style.RESET_ALL)

        # Sayfa içeriği analizi
        soup = BeautifulSoup(response.text, "html.parser")
        print(Fore.YELLOW + f"[INFO] Sayfa başlığı: {soup.title.string}" + Style.RESET_ALL)

        # Güvenlik testlerini başlat
        sql_injection_test(url)
        xss_test(url)
        directory_traversal_test(url)
        command_injection_test(url)
        csrf_test(url)
        header_injection_test(url)
        file_upload_test(url)
        ssl_tls_test(url)

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[ERROR] Siteye erişim başarısız: {e}" + Style.RESET_ALL)


def sql_injection_test(url):
    """
    SQL Injection açığı testini yapar.
    """
    test_url = url + "' OR '1'='1"
    response = requests.get(test_url)
    if response.status_code == 200 and "error" not in response.text.lower():
        print(Fore.RED + "[WARNING] Potansiyel SQL Injection açığı bulundu!" + Style.RESET_ALL)
        print(Fore.YELLOW + "[INFO] SQL Injection açığı için çözüm kaynakları:" + Style.RESET_ALL)
        print(Fore.CYAN + "1. OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection" + Style.RESET_ALL)
        print(Fore.CYAN + "2. OWASP Top Ten A1: Injection: https://owasp.org/www-project-top-ten/" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[INFO] SQL Injection açığı tespit edilmedi." + Style.RESET_ALL)


def xss_test(url):
    """
    XSS (Cross-Site Scripting) açığı testini yapar.
    """
    xss_payload = "<script>alert('XSS')</script>"
    test_url = url + "?search=" + xss_payload
    response = requests.get(test_url)
    if xss_payload in response.text:
        print(Fore.RED + "[WARNING] Potansiyel XSS açığı bulundu!" + Style.RESET_ALL)
        print(Fore.YELLOW + "[INFO] XSS açığı için çözüm kaynakları:" + Style.RESET_ALL)
        print(Fore.CYAN + "1. OWASP XSS: https://owasp.org/www-community/attacks/xss/" + Style.RESET_ALL)
        print(Fore.CYAN + "2. OWASP Top Ten A7: Cross-Site Scripting (XSS): https://owasp.org/www-project-top-ten/" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[INFO] XSS açığı tespit edilmedi." + Style.RESET_ALL)


def directory_traversal_test(url):
    """
    Directory Traversal açığını test eder.
    """
    test_url = url + "/../../etc/passwd"
    response = requests.get(test_url)
    if response.status_code == 200 and "root" in response.text:
        print(Fore.RED + "[WARNING] Potansiyel Directory Traversal açığı bulundu!" + Style.RESET_ALL)
        print(Fore.YELLOW + "[INFO] Directory Traversal açığı için çözüm kaynakları:" + Style.RESET_ALL)
        print(Fore.CYAN + "1. OWASP Directory Traversal: https://owasp.org/www-community/vulnerabilities/Path_Traversal" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[INFO] Directory Traversal açığı tespit edilmedi." + Style.RESET_ALL)


def command_injection_test(url):
    """
    Command Injection açığını test eder.
    """
    test_url = url + "?id=1; ls"
    response = requests.get(test_url)
    if "ls" in response.text:
        print(Fore.RED + "[WARNING] Potansiyel Command Injection açığı bulundu!" + Style.RESET_ALL)
        print(Fore.YELLOW + "[INFO] Command Injection açığı için çözüm kaynakları:" + Style.RESET_ALL)
        print(Fore.CYAN + "1. OWASP Command Injection: https://owasp.org/www-community/attacks/Command_Injection" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[INFO] Command Injection açığı tespit edilmedi." + Style.RESET_ALL)


def csrf_test(url):
    """
    CSRF (Cross-Site Request Forgery) açığını test eder.
    """
    test_url = url + "/submit?token=invalid_token"
    response = requests.get(test_url)
    if response.status_code == 200 and "invalid" in response.text:
        print(Fore.RED + "[WARNING] Potansiyel CSRF açığı bulundu!" + Style.RESET_ALL)
        print(Fore.YELLOW + "[INFO] CSRF açığı için çözüm kaynakları:" + Style.RESET_ALL)
        print(Fore.CYAN + "1. OWASP CSRF: https://owasp.org/www-community/attacks/csrf" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[INFO] CSRF açığı tespit edilmedi." + Style.RESET_ALL)


def header_injection_test(url):
    """
    HTTP Header Injection açığını test eder.
    """
    headers = {'X-Inject': 'test'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200 and 'test' in response.text:
        print(Fore.RED + "[WARNING] Potansiyel Header Injection açığı bulundu!" + Style.RESET_ALL)
        print(Fore.YELLOW + "[INFO] Header Injection açığı için çözüm kaynakları:" + Style.RESET_ALL)
        print(Fore.CYAN + "1. OWASP HTTP Response Splitting: https://owasp.org/www-community/vulnerabilities/HTTP_Response_Splitting" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[INFO] Header Injection açığı tespit edilmedi." + Style.RESET_ALL)


def file_upload_test(url):
    """
    File Upload Vulnerability açığını test eder.
    """
    file = {'file': ('test.php', '<php echo "test"; ?>', 'application/x-php')}
    response = requests.post(url + "/upload", files=file)
    if response.status_code == 200 and "test" in response.text:
        print(Fore.RED + "[WARNING] Potansiyel File Upload açığı bulundu!" + Style.RESET_ALL)
        print(Fore.YELLOW + "[INFO] File Upload açığı için çözüm kaynakları:" + Style.RESET_ALL)
        print(Fore.CYAN + "1. OWASP File Upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[INFO] File Upload açığı tespit edilmedi." + Style.RESET_ALL)


def ssl_tls_test(url):
    """
    SSL/TLS yapılandırma testini yapar.
    """
    if url.startswith("https"):
        response = requests.get(url, verify=False)  # Sertifika doğrulaması yapılmaz
        if response.status_code == 200:
            print(Fore.GREEN + "[INFO] SSL/TLS yapılandırması güvenli." + Style.RESET_ALL)
        else:
            print(Fore.RED + "[WARNING] SSL/TLS yapılandırması zayıf." + Style.RESET_ALL)
    else:
        print(Fore.RED + "[WARNING] SSL/TLS bağlantısı bulunmuyor!" + Style.RESET_ALL)


def main():
    """
    Kullanıcıdan URL alır ve siteyi tarar.
    """
    print(Fore.CYAN + "Web Uygulaması Güvenlik Taraması Aracı'na hoş geldiniz!" + Style.RESET_ALL)
    print(Fore.RED + "[Uyarı]: Bu terminal aracılığıyla yapılan sorgular tamamen website sahibini bilgilendirme amaçlıdır. Kötü amaçlı kullanılmamalıdır!" + Style.RESET_ALL)
    print(Fore.YELLOW + "---------------------------------------------" + Style.RESET_ALL)
    url = input(Fore.YELLOW + "Lütfen taramak istediğiniz web sitesi URL'sini girin (örn: https://example.com): " + Style.RESET_ALL).strip()

    if not url.startswith("http"):
        url = "http://" + url  # Protokol ekle

    # Domain adresinden IP'yi al
    domain = url.split("//")[-1].split("/")[0]  # domain kısmını al
    ip_address = domain_to_ip(domain)
    if ip_address:
        print(Fore.YELLOW + f"[INFO] Site IP adresi: {ip_address}" + Style.RESET_ALL)

    siteyi_tara(url)


if __name__ == "__main__":
    main()
