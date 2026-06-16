package com.example.portscanner;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.lang.reflect.Method;
import java.util.Map;

@RestController
@CrossOrigin(origins = "*")
public class ScanController {

    @Autowired
    private ApplicationContext ctx;

    @PostMapping(path = "/scan", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> scanPost(@RequestBody Map<String, String> body) {
        String target = body.get("target");
        return doScan(target);
    }

    @GetMapping("/scan")
    public ResponseEntity<?> scanGet(@RequestParam String target) {
        return doScan(target);
    }

    private ResponseEntity<?> doScan(String target) {
        if (target == null || target.isBlank()) {
            return ResponseEntity.badRequest().body("target boş");
        }

        try {
            Object result = invokeScannerBean(target);
            if (result == null) {
                String msg = "Tarama servisi bulunamadı. Lütfen servis sınıfı ve method adını belirtin veya bir bean olarak kaydedin.";
                return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).body(msg);
            }

            if (result instanceof String) {
                return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(result);
            } else {
                return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(result);
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    private Object invokeScannerBean(String target) throws Exception {
        String[] candidateMethodNames = new String[]{"scan", "scanTarget", "scanPorts", "startScan", "runScan", "performScan"};

        String[] beanNames = ctx.getBeanDefinitionNames();
        for (String beanName : beanNames) {
            Object bean = ctx.getBean(beanName);
            Class<?> cls = bean.getClass();
            for (String mname : candidateMethodNames) {
                try {
                    Method m = cls.getMethod(mname, String.class);
                    // invoke and return
                    return m.invoke(bean, target);
                } catch (NoSuchMethodException ignored) {
                }
            }
        }

        return null;
    }
}
