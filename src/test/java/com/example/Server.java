package com.example;

import pro.nnnteam.httplib.HTTPResult;
import pro.nnnteam.httplib.annotation.Route;
import pro.nnnteam.httplib.annotation.StartEntry;

@StartEntry
public class Server {
    @Route(path = "/")
    public static String indexPage() {
        return "Hello world";
    }

    @Route(path = "/test/resultcode")
    public static HTTPResult textPage() {
        return new HTTPResult.Builder()
                .data("Test result code")
                .resultCode(404)
                .build();
    }

    @Route(path = "@404")
    public static HTTPResult error404() {
        return new HTTPResult.Builder()
                .data("Not found!")
                .resultCode(404)
                .build();
    }
}