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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@SpringBootApplication
@RestController
@CrossOrigin(origins = "*")
public class PortScanner {

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

    private Map<String, Object> performScan(String urlInput) {
        Map<String, Object> response = new HashMap<>();
        if (urlInput == null || urlInput.trim().isEmpty()) {
            response.put("error", "Hedef URL girilmedi.");
            return response;
        }

        String temizUrl = urlInput.replace("https://", "").replace("http://", "").split("/")[0];

        try {
            InetAddress inetAddress = InetAddress.getByName(temizUrl);
            String hedefIp = inetAddress.getHostAddress();
            
            response.put("domain", temizUrl);
            response.put("ip", hedefIp);

            int[] kritikPortlar = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8080};
            List<Map<String, String>> sonuclar = new ArrayList<>();

            for (int port : kritikPortlar) {
                String banner = getPortBanner(hedefIp, port);
                if (banner != null) {
                    Map<String, String> portSonuc = new HashMap<>();
                    portSonuc.put("port", String.valueOf(port));
                    portSonuc.put("durum", "ACIK");
                    portSonuc.put("banner", banner);
                    sonuclar.add(portSonuc);
                }
            }
            response.put("ports", sonuclar);
            
        } catch (IOException e) {
            response.put("error", "Alan adi cozumlenemedi! " + e.getMessage());
        }

        return response;
    }

    private String getPortBanner(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 300);
            
            try {
                socket.setSoTimeout(1000); 
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