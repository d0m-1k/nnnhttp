package com.example;

import pro.nnnteam.httplib.annotation.Route;
import pro.nnnteam.httplib.annotation.StartEntry;

@StartEntry
public class Main {
    @Route(path = "/")
    public static void indexPage() {

    }
}