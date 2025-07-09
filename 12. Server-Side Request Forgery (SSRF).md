# 12. Server-Side Request Forgery (SSRF)

## 12.1 SSRF Nedir?

Server-Side Request Forgery (SSRF), saldırganın uygulamanın sunucu tarafındaki HTTP istemcisi (örneğin `HttpClient`, `WebRequest`) aracılığıyla kendi belirlediği bir hedefe istek göndermesini sağladığı bir güvenlik zafiyetidir.

SSRF saldırılarıyla şunlar gerçekleştirilebilir:

* İç ağdaki sistemlere erişim (intranet, metadata servisleri)
* Güvenlik duvarı arkasındaki hizmetlerin taranması
* Yerel dosya sistemine veya API’lere erişim
* Uygulama üzerinde DoS
* Gelişmiş senaryolarda RCE (özellikle cloud metadata servisleri üzerinden)

---

## 12.2 SSRF Nasıl Ortaya Çıkar?

Uygulama, kullanıcıdan aldığı bir URL’yi doğrudan `HttpClient` gibi istemci araçlarıyla çağırıyorsa ve bu URL doğrulanmıyorsa SSRF açığı oluşur.

### Tehlikeli Örnek

```csharp
public async Task<IActionResult> Fetch(string url)
{
    var client = new HttpClient();
    var response = await client.GetStringAsync(url);
    return Content(response);
}
```

Bu yapı ile saldırgan şu URL’leri hedefleyebilir:

* `http://127.0.0.1:5000/admin`
* `http://169.254.169.254/latest/meta-data/` (AWS metadata)
* `file:///etc/passwd`

---

## 12.3 SSRF Varyantları

| Tür                    | Açıklama                                                                          |
| ---------------------- | --------------------------------------------------------------------------------- |
| **Basic SSRF**         | URL parametresi ile hedef sistemdeki servislere erişim                            |
| **Blind SSRF**         | Uygulama response dönmese bile arka planda isteği gerçekleştirir                  |
| **Authenticated SSRF** | Uygulama servis içi kimlik bilgileriyle dışa istek atar                           |
| **Out-of-Band SSRF**   | DNS veya external host üzerinden tetiklenir, yanıt gelmese de loglarda iz bırakır |

---

## 12.4 SSRF ile Saldırı Senaryoları

### 12.4.1 Metadata Servisi Erişimi (AWS Örneği)

```
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Bu istek üzerinden temporary credentials ele geçirilebilir ve AWS ortamında IAM yetkileri elde edilebilir.

### 12.4.2 Localhost Üzerinden Yönetici Paneline Erişim

```
GET http://localhost:8000/admin
```

Eğer admin paneli sadece loopback adresinden erişilebiliyorsa, SSRF ile bu sınırlama aşılır.

---

## 12.5 SSRF Önleme Stratejileri

### 12.5.1 IP Whitelist / Blacklist

Yalnızca belirli domain’lere veya IP aralıklarına istek gönderilmesine izin verilir.

```csharp
var allowedDomains = new[] { "example.com", "api.trusted.com" };
var host = new Uri(url).Host;

if (!allowedDomains.Contains(host))
    return BadRequest("Yasaklı hedef.");
```

### 12.5.2 DNS Resolution Kontrolü

Bazı SSRF saldırıları DNS rebinding veya host spoofing içerir. Bu nedenle IP adresleri resolve edildikten sonra özel IP aralıkları engellenmelidir.

### 12.5.3 URL Parse ve Protokol Kontrolü

```csharp
var uri = new Uri(url);

if (uri.Scheme != "http" && uri.Scheme != "https")
    return BadRequest("Geçersiz protokol.");
```

### 12.5.4 File ve FTP Protokollerini Engelleme

`file://`, `ftp://`, `gopher://` gibi protokollerle yapılan SSRF saldırıları engellenmelidir.

---

## 12.6 SSRF Test Payloadları

* `http://127.0.0.1/`
* `http://localhost/`
* `http://169.254.169.254/` (AWS)
* `http://[::1]/`
* `http://google.com@127.0.0.1/` (bypass için)
* `http://127.0.0.1%2F%2E%2E/` (encoding ile bypass)

---

## 12.7 Güvenli Kodlama Örneği

```csharp
public async Task<IActionResult> SecureFetch(string inputUrl)
{
    var uri = new Uri(inputUrl);
    var ip = Dns.GetHostAddresses(uri.Host).First();

    if (IPAddress.IsLoopback(ip) || ip.ToString().StartsWith("169.254."))
        return Forbid();

    var allowedDomains = new[] { "example.com", "trusted.com" };
    if (!allowedDomains.Contains(uri.Host))
        return Forbid();

    var client = new HttpClient();
    var content = await client.GetStringAsync(uri);
    return Content(content);
}
```

---

## 12.8 Gerçek Dünya Örneği

**CVE-2019-11043 – PHP-FPM + Nginx SSRF + RCE**

Bir dosya yükleme endpoint'i, SSRF yoluyla localhost üzerinde çalışan PHP-FPM servisine istek gönderiyordu. Bu istek özel bir query parametresi içerdiğinde, tam yetkili RCE açığına dönüştü.

---

## 12.9 Güvenlik Testi Önerileri

| Test Adımı                             | Amaç                           |
| -------------------------------------- | ------------------------------ |
| Özel IP aralıklarına istek             | Localhost / metadata erişimi   |
| DNS logging endpoint                   | Blind SSRF tespiti             |
| URL encoding ile bypass                | Filtre atlatma denemesi        |
| Header injection                       | Host: değiştirerek yönlendirme |
| X-Forwarded-For / X-Host manipülasyonu | Reverse proxy arkası hedefleme |

---

## 12.10 Koruma Checklist

* [ ] Uygulama dış URL’lere istek gönderiyor mu?
* [ ] URL parametresi kullanıcıdan doğrudan mı alınıyor?
* [ ] Hedef IP/Domain whitelist ile sınırlı mı?
* [ ] Localhost, 127.0.0.1, 169.254.\* gibi IP’lere erişim engellenmiş mi?
* [ ] File, FTP gibi protokoller bloklanmış mı?
* [ ] Blind SSRF testleri loglarla tespit edilebiliyor mu?

SSRF, dış dünyaya açık olmasa da uygulamanın iç mimarisi hakkında bilgi edinmeyi ve hizmetlere erişmeyi sağlayan kritik bir açıklıktır. Modern bulut mimarilerinde SSRF, IAM yetkilerinin ele geçirilmesiyle birleştiğinde zincirleme saldırıların temelini oluşturur. Bu nedenle SSRF’e karşı savunma hem uygulama hem de altyapı seviyesinde uygulanmalıdır.
