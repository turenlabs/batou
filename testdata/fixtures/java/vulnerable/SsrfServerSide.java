package com.example.vulnerable;

import java.io.InputStream;
import java.net.URL;
import java.net.HttpURLConnection;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

public class SsrfServerSide {

    // VULNERABLE: new URL(userInput).openStream()
    public String fetchUrl(HttpServletRequest request) throws Exception {
        String targetUrl = request.getParameter("url");
        InputStream is = new URL(targetUrl).openStream();
        return new String(is.readAllBytes());
    }

    // VULNERABLE: new URL(userInput).openConnection()
    public String proxyRequest(@RequestParam String url) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("GET");
        return conn.getResponseMessage();
    }

    // VULNERABLE: RestTemplate with user-controlled URL
    @GetMapping("/api/proxy")
    public String restProxy(@RequestParam String serviceUrl) {
        RestTemplate restTemplate = new RestTemplate();
        return restTemplate.getForObject(serviceUrl, String.class);
    }

    // VULNERABLE: WebClient with user-controlled URL
    @GetMapping("/api/fetch")
    public String webClientFetch(@RequestParam String endpoint) {
        return WebClient.create(endpoint)
                .get()
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }
}
