package com.example.safe;

import java.io.IOException;
import java.net.URI;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class SsrfHttpClientsSafe extends HttpServlet {

    private static final Set<String> ALLOWED_HOSTS = Set.of(
            "api.example.com", "cdn.example.com");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Safe: hardcoded URL, no user input
        String apiUrl = "https://api.example.com/data";
        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(apiUrl);
        httpclient.execute(httpGet);

        // Safe: hardcoded OkHttp request
        OkHttpClient okClient = new OkHttpClient();
        Request okRequest = new Request.Builder()
                .url("https://api.example.com/status")
                .build();
        Response okResponse = okClient.newCall(okRequest).execute();
    }
}
