package com.example;

import pro.nnnteam.httplib.HTTPResult;
import pro.nnnteam.httplib.annotation.*;

import java.nio.charset.StandardCharsets;

@StartEntry
public class Server {

    @Route(path = "/", method = "GET")
    public String indexPage() {
        return "Hello world";
    }

    @Route(path = "/user/{id}", method = "GET")
    public String getUser(@PathParam("id") int userId) {
        return "User ID: " + userId;
    }

    @Route(path = "/search", method = "GET")
    public String search(@QueryParam("q") String query) {
        if (query == null || query.isEmpty()) return "No query provided";
        return "Search results for: " + query;
    }

    @Route(path = "/echo", method = "POST")
    public String echo(@Body String body) {
        return "Echo: " + body;
    }

    @Route(path = "/custom", method = "GET")
    public HTTPResult customResponse() {
        return new HTTPResult.Builder()
                .data("Custom response".getBytes(StandardCharsets.UTF_8))
                .resultCode(201)
                .contentType("text/plain; charset=utf-8")
                .putHeader("X-Custom-Header", "foobar")
                .build();
    }

    @Route(path = "/json", method = "GET")
    public HTTPResult jsonResponse() {
        String json = "{\"message\": \"Hello JSON\"}";
        return new HTTPResult.Builder()
                .data(json.getBytes(StandardCharsets.UTF_8))
                .contentType("application/json")
                .build();
    }

    @Route(path = "@404", method = "GET")
    public HTTPResult notFound() {
        return new HTTPResult.Builder()
                .data("Custom 404 Page".getBytes(StandardCharsets.UTF_8))
                .resultCode(404)
                .contentType("text/plain")
                .build();
    }
}