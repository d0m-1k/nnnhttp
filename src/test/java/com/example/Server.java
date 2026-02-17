package com.example;

import pro.nnnteam.httplib.annotation.Route;
import pro.nnnteam.httplib.annotation.StartEntry;

@StartEntry
public class Server {
    @Route(path = "/")
    public static String indexPage() {
        return "Hello world";
    }
}