# Huawei CLI

Agent başlangıç rehberi: [AGENTS.md](AGENTS.md). Kısa giriş: [llm.txt](llm.txt).

v2.0.1 kaynak kodunu kullanan Linux ve Windows x64 CLI. Çalıştırılabilir dosyalar: Linux `src/publish/huawei`, Windows `src/publish/windows/huawei.exe`.
GNU GPL v2 lisansı ve upstream kaynakları bu depoda korunmuştur.

## Kullanım

Bilgi verilmezse GUI ile aynı varsayılanlar kullanılır: `192.168.1.1`, `admin`, `superonline`. Parola önceliği: `--password-file`, ardından `HUAWEI_PASSWORD`, ardından varsayılan. Açıkça verilen boş parola dosyası hata verir. Komut satırı argümanına parola yazmayın. Varsayılan kullanıcı `admin`, adres `192.168.1.1`; `--user` ve `--host` ile değişir.

```sh
huawei help
huawei info --host 192.168.1.1 --password-file /private/router-password
huawei wifi get
huawei wifi set --band 1 --ssid Ev --hidden false
huawei wifi security --band 1 --encryption aes
huawei dns set --primary 1.1.1.1 --secondary 1.0.0.1
huawei firewall set --level high
huawei tr069 set --enabled false --periodic false
huawei backup config --output backup.cfg
huawei backup profile --output profile.json
huawei restore config --file backup.cfg
huawei restore profile --file profile.json
```

`wifi set --psk-env WIFI_KEY` parolayı belirtilen ortam değişkeninden okur. `wifi security --band <instance> --encryption aes|tkip|both` bandın WPA şifreleme modunu ayarlar; **TKIP açıkken 802.11n/ax yüksek hız modları devre dışı kaldığı için `aes` kablosuz hız için en etkili değişikliktir.** Yazdıktan sonra bandı geri okuyup doğrular (`state=verified`). `wifi split` iki bandı ayırır. `alg set --file alg.json` örneğin `{"SIP":false}` alır; desteklenen anahtarları `alg get` verir.

`wan get` WAN durumunu okur. `wan set --file wan.json` seçilen WAN nesnesine form alanlarını yazar; örnek dosya `{"x.MaxMRUSize":"1492"}`. `--domain` ile bağlantı seçilebilir. Alanların firmware tarafından desteklenmesi gerekir.

## Windows (PowerShell)

.NET 9 SDK ile Windows çıktısı oluşturulur; self-contained EXE çalıştırmak için .NET kurulumu gerekmez:

```powershell
dotnet publish src/HekzOntRace.Cli.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o src/publish/windows
.\src\publish\windows\huawei.exe info
$env:HUAWEI_PASSWORD = 'kendi-parolaniz'
.\src\publish\windows\huawei.exe wifi get --user admin
.\src\publish\windows\huawei.exe credentials recover --python 'C:\Path\python.exe' --output-dir "$env:USERPROFILE\huawei-backups"
```

Kurtarma için Windows Python ortamında `python -m pip install paramiko pysmb` gerekir; WSL Python yolu Windows EXE'ye verilmez. stdout ve stderr UTF-8 kullanır. Windows yedekleri klasörün NTFS izinlerini devralır; Linux'taki 0600 izni Windows için geçerli değildir. Yedekleri özel kullanıcı klasöründe saklayın.

Windows testleri aynı paketle çalışır:

```powershell
$env:HUAWEI_CLI = (Resolve-Path .\src\publish\windows\huawei.exe).Path
python -m unittest discover -s tests -v
```

## Genel okuma/yazma

```sh
huawei http get --path html/ssmp/deviceinfo/deviceinfo.asp
huawei http post --path 'set.cgi?x=InternetGatewayDevice.ManagementServer' --file fields.json
huawei config get --file backup.xml --xpath '//DeviceInfo'
huawei config edit --file backup.xml --xpath '//DeviceInfo' --attribute ModelName --value-env NEW_VALUE --output changed.xml
huawei config decrypt --file encrypted.cfg --output plain.xml
huawei credentials get --show-secrets
huawei ssh exec --command-file command.txt --host-key SHA256:TRUSTED_FINGERPRINT
```

`http post` JSON string değerlerinden form oluşturur, güncel oturum token'ını ekler. Firmware'e özel uçları önce cihaz sayfasından inceleyin. XML düzenleme yerel dosyada gerçekleşir; `restore config` ayrı yazma işlemidir. SSH sunucusu exec kanalını desteklemeli; bazı Huawei WAP kabukları yalnız interaktif kanal kabul edebilir. SSH anahtarı güvenilir bir kaynaktan alınmalıdır.

`credentials recover --user admin --python /path/to/python --output-dir /private/backups` upstream USB/SMB/SFTP kurtarma akışını çalıştırır. Python ortamında `paramiko` ve `pysmb` gerekir. USB bellek gerekir; servis ayarlarını değiştirir ve geçici hesap oluşturur. Başka SFTP hesaplarını silen upstream adım kaldırılmıştır. Servislerin önceki durumuna eksiksiz dönüş garanti edilmez.

`access password --user sUser --new-password-env NEW_PASSWORD --method web --enable-shell true` mevcut sUser parolasıyla web yapılandırma akışını çalıştırır. `--method race` eski flash yarış akışıdır; fiziksel güç kesme zamanlaması gerektirir, tamamen otonom değildir. Başarılı dönüş yeni parolanın cihazda etkinleştiğinin kanıtı değildir.

## Otomasyon sözleşmesi

stdout tek JSON nesnesi, stderr günlüklerdir. Komutlar soru sormaz; yazma komutları hemen uygulanır. `help` komut ve seçenek envanterini JSON verir.

| Çıkış | Anlam |
|---|---|
| 0 | Okuma veya doğrulanmış işlem |
| 2 | Girdi/dosya doğrulama hatası |
| 3 | Kimlik doğrulama hatası |
| 4 | Ağ/çalıştırma hatası |
| 5 | Gönderildi ama doğrulanmadı veya kısmi veri |
| 130 | İptal/zaman aşımı |

`state=verified` geri okuma kontrolünü, `submitted` yalnız gönderilmiş/denenmiş işlemi belirtir. `ok=true` ile birlikte `submitted` gelebilir; bunu ayarın uygulandığı şeklinde yorumlamayın. Yazma hatasında kör tekrar yapmayın; mevcut durumu okuyun. `--timeout` saniye cinsindendir (varsayılan 180); upstream kurtarma/temizlik işlemleri iptale gecikmeli yanıt verebilir.

Yapılandırılmış çıktıda parolalar varsayılan maskelenir, `--show-secrets` açar. Ham HTTP/SSH çıktıları ve yedek dosyaları sır içerebilir. Yeni CLI yedekleri Linux'ta 0600 izinle açılır ve mevcut dosyanın üzerine yazılmaz. Restore öncesi yerel konfigürasyon yedeği alınır. Firmware/model uyumluluğu yine cihazda doğrulanmalıdır.

## Doğrulama ve derleme

```sh
dotnet publish src/HekzOntRace.Cli.csproj -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -o src/publish
src/publish/huawei self-test
python3 -m unittest discover -s tests -v
```

Otomatik testler yalnız loopback sahte modem kullanır. Gerçek cihazda varsayılan giriş ve USB/SMB/SFTP kurtarma akışı başarılı oldu. Tüm ayar yazımları, SSH ve fiziksel flash race yöntemi donanımda test edilmedi. Windows üzerinde 31 entegrasyon testi geçti; symlink testi yetki bulunmadığı için atlandı. Altı dahili kontrol geçti. Windows x64 EXE Windows üzerinde çalıştırıldı; gerçek modem okuması kısmi veri döndürdü. Windows kurtarma bağımlılıkları mevcut, fakat kurtarma/yazma akışı Windows üzerinde cihazda tekrar çalıştırılmadı.

Genişletilmiş paket 32 entegrasyon testi içerir; parametrik alt senaryolar ayrıca çalışır. Kapsam: oturum doğrulama, eksik token, yok sayılan DNS/ALG/TR-069/firewall yazıları, kısmi veriler, geçersiz form JSON'u, seçenek sınırları, DNS/SSID doğrulaması, XML DTD ve belirsiz XPath reddi, parola maskeleme, dosya izinleri ve symlink üzerinden üzerine yazmanın engellenmesi. Altı dahili kontrol kripto roundtrip, HMAC bozulması, parola doğrulama, maskeleme ve komut ayrıştırmayı kapsar. Bu sayılar bütün firmware davranışlarının test edildiği anlamına gelmez.
