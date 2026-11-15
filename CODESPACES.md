# GitHub Codespaces'te çalıştırma

Depodaki `.devcontainer` ayarları uygulama için Python ortamını ve PostgreSQL 16 veritabanını birlikte başlatır. İlk açılışta Python bağımlılıkları kurulur, uygulama 10000 portunda otomatik çalışır.

1. Depoyu GitHub'a gönderin ve GitHub'da açın.
2. **Code → Codespaces → Create codespace** seçin.
3. Codespace hazır olunca uygulama bağlantısını açın. Bağlantı görünmüyorsa VS Code'daki **Ports** sekmesinden 10000 portunu açın.

Port varsayılan olarak özeldir. Yalnızca Codespace sahibi GitHub oturumuyla erişebilir. Başka cihazlardan/kişilerden erişim için **Ports → 10000 → Port Visibility → Public** seçin ve HTTPS bağlantısını paylaşın. Bağlantıyı bilen herkes uygulamaya erişebilir. Codespace durduğunda uygulama da durur; yeniden açıldığında otomatik başlar. Ücretsiz kullanım kişisel GitHub hesabının aylık Codespaces kotasına tabidir.

Üyelik veritabanı PostgreSQL Docker volume'ünde tutulur; Codespace durdurma ve container rebuild işlemlerinde korunur. Codespace'i silmek veritabanı volume'ünü de silebilir. Bu ortam deneme ve geliştirme içindir; canlı kullanıcı verisini burada tutmayın.

Google OAuth'u denemek için Google Console'daki authorized redirect URI alanına Codespace'in 10000 port HTTPS adresinin sonuna `/auth/google/callback` ekleyerek girin. Codespace URL'si değişirse bu değeri de güncelleyin. Gerçek OAuth ve SMTP sırlarını yapılandırma dosyalarına eklemeyin; Codespaces secrets/ortam değişkenlerini kullanın. Üretim için HTTPS, kalıcı ve güçlü `CSRF_SECRET` ile yedeklenen harici PostgreSQL gerekir.
