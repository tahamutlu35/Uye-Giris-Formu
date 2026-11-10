# Kavrix üyelik ve giriş kurulumu

Uygulama mevcut Python standart kütüphanesi sunucusunu ve SQLite veritabanını kullanır. Ön yüz HTML/CSS/JavaScript olarak kalır. Google OAuth ve parola sıfırlama için harici hizmet ayarları gereklidir; bu değerler kaynak koda eklenmez.

## Yerelde çalıştırma

Python 3.10 veya üzeri ile proje klasöründe:

```powershell
Copy-Item .env.example .env
python app.py
```

`app.py`, proje klasöründeki `.env` dosyasını başlatma sırasında okur; işletim sistemi ortam değişkenleri dosyadaki değerlerin önüne geçer. Örnek değerleri gerçek sağlayıcı bilgilerinizle doldurun. İsterseniz PowerShell ortam değişkenleriyle de ayarlayabilirsiniz:

```powershell
$env:GOOGLE_CLIENT_ID = "..."
$env:GOOGLE_CLIENT_SECRET = "..."
$env:GOOGLE_REDIRECT_URI = "http://kavrix.uyelik/auth/google/callback"
$env:SITE_URL = "http://kavrix.uyelik"
$env:SMTP_HOST = "smtp.example.com"
$env:SMTP_PORT = "587"
$env:SMTP_USER = "..."
$env:SMTP_PASSWORD = "..."
$env:SMTP_FROM = "destek@example.com"
python app.py
```

Şifre sıfırlama e-postası SMTP ayarları yapılmadan gönderilemez. E-posta adresinin sistemde bulunup bulunmadığını ifşa etmemek için istek yanıtı her zaman genel bir bilgilendirme gösterir.

## Google OAuth kurulumu

1. Google Cloud Console'da bir proje oluşturun/seçin ve **Google Auth Platform** ekranında uygulama adını, destek e-postasını ve izin verilen kullanıcıları tanımlayın. `openid`, `email` ve `profile` kapsamları kullanılır.
2. **Credentials → Create credentials → OAuth client ID → Web application** seçin.
3. Authorized redirect URI alanına tam olarak `GOOGLE_REDIRECT_URI` değerini ekleyin. Yerel varsayılan: `http://kavrix.uyelik/auth/google/callback`.
4. Oluşturulan Client ID ve Client Secret değerlerini sunucunun ortam değişkenlerine koyun. Secret değerini HTML, JavaScript veya depoya eklemeyin.
5. Üretimde HTTPS alan adını `SITE_URL` olarak ayarlayın ve aynı alan adındaki callback URI'yi Google'a kaydedin. `GOOGLE_REDIRECT_URI` de bu callback ile karakter karakter aynı olmalıdır.

## Üretim notları

Bu küçük standart kütüphane sunucusu, TLS sonlandıran bir reverse proxy arkasında çalıştırılmalıdır. `SITE_URL` mutlaka HTTPS olunca oturum ve OAuth durum çerezleri `Secure`, her durumda `HttpOnly` ve `SameSite=Lax` olur. Sunucu yaln?zca 127.0.0.1 ?zerinde dinler; PORT varsay?lan olarak 80 olur. 

### GitHub Codespaces verileri

Uygulama `members.db` dosyasini varsayilan olarak proje klasorune yazar. Codespaces icinde bu klasor `/workspaces` altindaysa SQLite dosyasi Codespace durdurulup yeniden baslatildiginda ve container rebuild edildiginde korunur. Uygulama prosesi yeniden baslayinca `sessions` tablosu SQLite dosyasinda kaldigi icin oturumlar devam eder. Veritabani silinir, `MEMBERS_DB_PATH` gecici bir konuma ayarlanir veya Codespace silinirse uyeler ve oturumlar kaybolur. Canli kullanici verisi icin Codespaces dosya alanini yedek/kalici veritabani olarak kabul etmeyin.

`CSRF_SECRET` icin her ortamda kalici, rastgele ve en az 32 baytlik bir deger kullanin. Bos birakilirsa her uygulama baslangicinda gecici anahtar uretilir; restart sonrasinda acik formlardaki CSRF tokenlari gecersiz olur. Deploy ayarlarinda gercek degerleri secret/environment variable olarak tutun, `.env` dosyasini Git'e eklemeyin. `SITE_URL` HTTPS olmali; bu deger HTTPS `Secure` cerezlerini etkinlestirir.

GitHub Codespaces, `/workspaces` altindaki dosyalarin stop/start ve container rebuild boyunca korundugunu aciklar: https://docs.github.com/en/codespaces/developing-in-a-codespace/rebuilding-the-container-in-a-codespace
