package com.example.vulnerable;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequestFactory;

public class SsrfHttpClients extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String targetUrl = request.getParameter("url");

        // Apache HttpClient - HttpGet
        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(targetUrl);
        httpclient.execute(httpGet);

        // Apache HttpClient - HttpPost
        HttpPost httpPost = new HttpPost(targetUrl);
        httpclient.execute(httpPost);

        // Apache HttpClient - HttpPut
        HttpPut httpPut = new HttpPut(targetUrl);
        httpclient.execute(httpPut);

        // Apache HttpClient - HttpDelete
        HttpDelete httpDelete = new HttpDelete(targetUrl);

        // Apache HttpClient - HttpPatch
        HttpPatch httpPatch = new HttpPatch(targetUrl);

        // Apache HttpClient - setURI
        httpGet.setURI(java.net.URI.create(targetUrl));

        // Apache URIBuilder
        URIBuilder uriBuilder = new URIBuilder(targetUrl);

        // OkHttp - Request.Builder.url
        OkHttpClient okClient = new OkHttpClient();
        Request okRequest = new Request.Builder()
                .url(targetUrl)
                .build();
        Response okResponse = okClient.newCall(okRequest).execute();

        // Google HTTP Client - GenericUrl
        GenericUrl genericUrl = new GenericUrl(targetUrl);
    }
}
