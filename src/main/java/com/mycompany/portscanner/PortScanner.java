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
import java.util.concurrent.*;

@SpringBootApplication
@RestController
@CrossOrigin(origins = "*")
public class PortScanner {

    private static final int[] KRITIK_PORTLAR = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8080};

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

    public Map<String, Object> performScan(String urlInput) {
        Map<String, Object> response = new HashMap<>();
        if (urlInput == null || urlInput.trim().isEmpty()) {
            response.put("error", "Hedef URL girilmedi.");
            return response;
        }

        String temizUrl = urlInput.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0];

        try {
            InetAddress inetAddress = InetAddress.getByName(temizUrl);
            String hedefIp = inetAddress.getHostAddress();

            response.put("domain", temizUrl);
            response.put("ip", hedefIp);

            List<Map<String, String>> sonuclar = new ArrayList<>();

            int threadSayisi = Math.min(KRITIK_PORTLAR.length, 16);
            ExecutorService executor = Executors.newFixedThreadPool(threadSayisi);
            List<Future<Map<String, String>>> futures = new ArrayList<>();

            for (int port : KRITIK_PORTLAR) {
                Callable<Map<String, String>> task = () -> {
                    String banner = getPortBanner(hedefIp, port);
                    if (banner != null) {
                        Map<String, String> portSonuc = new HashMap<>();
                        portSonuc.put("port", String.valueOf(port));
                        portSonuc.put("durum", "ACIK");
                        portSonuc.put("banner", banner);
                        return portSonuc;
                    }
                    return null;
                };
                futures.add(executor.submit(task));
            }

            for (Future<Map<String, String>> future : futures) {
                try {
                    Map<String, String> sonuc = future.get();
                    if (sonuc != null) {
                        sonuclar.add(sonuc);
                    }
                } catch (InterruptedException | ExecutionException e) {
                }
            }

            executor.shutdown();
            response.put("ports", sonuclar);

        } catch (IOException e) {
            response.put("error", "Alan adi cozumlenemedi! " + e.getMessage());
        }

        return response;
    }

    private String getPortBanner(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 400);
            socket.setSoTimeout(1200);

            if (port == 80 || port == 443 || port == 8080) {
                try {
                    OutputStream os = socket.getOutputStream();
                    String httpRequest = "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: PortScanner/1.0\r\nConnection: close\r\n\r\n";
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

            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                char[] buffer = new char[1024];
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
}