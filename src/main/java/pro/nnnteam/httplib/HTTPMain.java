package pro.nnnteam.httplib;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.nnnteam.httplib.annotation.Route;
import pro.nnnteam.httplib.annotation.StartEntry;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class HTTPMain {
    private static final Logger LOG = LoggerFactory.getLogger(HTTPMain.class);
    private static final String CONFIG_FILE = "nnnhttp.properties";
    private static HashMap<Route, Method> handlers = new HashMap<>();
    private static HttpServer server = null;
    private static Properties properties;

    private static boolean isRunningFromJar() {
        CodeSource source = HTTPMain.class.getProtectionDomain().getCodeSource();
        if (source != null) {
            URL location = source.getLocation();
            if (location != null) {
                String path = location.getPath();
                return path != null && path.toLowerCase().endsWith(".jar");
            }
        }
        return false;
    }

    private static Properties loadProperties(String resourceName) {
        Properties props = new Properties();
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourceName)) {
            if (is == null) throw new RuntimeException("Config file not found in classpath: " + resourceName);
            props.load(is);
        } catch (IOException err) {
            throw new RuntimeException("Config file load error: " + resourceName, err);
        }
        return props;
    }

    private static Class<?> findMainClass(Properties props) {
        String mainClass = props.getProperty("mainClass", null);

        if (mainClass == null) {
            // TODO: Поиск класса вручную
            LOG.debug("mainClass is null");
            return null;
        }

        if (mainClass.isEmpty()) {
            LOG.debug("mainClass is empty");
            return null;
        }

        try {
            Class<?> clazz = Class.forName(mainClass);
            if (clazz.isAnnotationPresent(StartEntry.class)) {
                return clazz;
            }
            LOG.debug("{} not annotated @StartEntry", clazz.getName());
        } catch (ClassNotFoundException ignored) {
            LOG.debug("Class Not Found Exception handled");
        }

        return null;
    }

    private static void registerRouteHandlers(Class<?> clazz) {
        for (Method method : clazz.getDeclaredMethods()) {
            Route route = method.getAnnotation(Route.class);
            if (route != null) {
                if (method.getParameterCount() == 0) {
                    handlers.put(route, method);
                    LOG.debug("Registered route {} -> {}", route.path(), method.getName());
                } else {
                    LOG.warn("Method {} annotated with @Route has parameters, ignored", method.getName());
                }
            }
        }
    }

    private static SSLContext createSSLContext(Properties props) {
        String keyStorePath = props.getProperty("server.ssl.keyStore");
        if (keyStorePath == null || keyStorePath.trim().isEmpty()) {
            LOG.warn("SSL keystore not configured, using default SSL context");
            try {
                return SSLContext.getDefault();
            } catch (NoSuchAlgorithmException err) {
                throw new RuntimeException("Failed to get default SSL context", err);
            }
        }

        String keyStorePassword = props.getProperty("server.ssl.keyStorePassword", "");
        String keyPassword = props.getProperty("server.ssl.keyPassword", keyStorePassword);
        String trustStorePath = props.getProperty("server.ssl.trustStore");
        String trustStorePassword = props.getProperty("server.ssl.trustStorePassword", "");
        String keyStoreType = props.getProperty("server.ssl.keyStoreType", KeyStore.getDefaultType());
        String trustStoreType = props.getProperty("server.ssl.trustStoreType", KeyStore.getDefaultType());

        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            try (InputStream is = openInputStream(keyStorePath)) {
                keyStore.load(is, keyStorePassword.toCharArray());
            }

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keyPassword.toCharArray());

            TrustManagerFactory trustManagerFactory = null;
            if (trustStorePath != null && !trustStorePath.trim().isEmpty()) {
                KeyStore trustStore = KeyStore.getInstance(trustStoreType);
                try (InputStream is = openInputStream(trustStorePath)) {
                    trustStore.load(is, trustStorePassword.toCharArray());
                }
                trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trustStore);
            }

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(
                    keyManagerFactory.getKeyManagers(),
                    trustManagerFactory != null ? trustManagerFactory.getTrustManagers() : null,
                    new SecureRandom()
            );

            return sslContext;

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException |
                 CertificateException | UnrecoverableKeyException | KeyManagementException err) {
            LOG.error("Failed to create SSL context: {}", err.getMessage(), err);
            throw new RuntimeException("SSL configuration failed", err);
        }
    }

    private static InputStream openInputStream(String path) throws IOException {
        if (path.startsWith("res://")) {
            String resourcePath = path.substring(6);
            InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourcePath);
            if (is == null) throw new IOException("Resource not found in classpath: " + resourcePath);
            return is;
        } else return new FileInputStream(path);
    }

    public static void main(String[] args) {
        properties = loadProperties(CONFIG_FILE);
        Class<?> mainClass = findMainClass(properties);
        if (mainClass == null) {
            LOG.error("Cannot find main class.");
            throw new IllegalStateException("Main class not found");
        }
        registerRouteHandlers(mainClass);

        Map<String, Map<String, Method>> pathHandlers = new HashMap<>();
        handlers.forEach((route, method) -> {
            pathHandlers.computeIfAbsent(route.path(), k -> new HashMap<>()).put(route.method().toLowerCase(), method);
        });

        try {
            String host = properties.getProperty("server.host", "0.0.0.0");
            int port = Integer.parseInt(properties.getProperty("server.port", "8080"));
            int backlog = Integer.parseInt(properties.getProperty("server.backlog", "5"));
            boolean enableHttps = "true".equals(properties.getProperty("server.ssl.enabled", "false"));
            InetSocketAddress addr = new InetSocketAddress(host, port);

            if (enableHttps) {
                server = HttpsServer.create(addr, backlog);
                SSLContext sslContext = createSSLContext(properties);
                ((HttpsServer) server).setHttpsConfigurator(new HttpsConfigurator(sslContext));
            } else {
                server = HttpServer.create(addr, backlog);
            }

            server.createContext("/", exchange -> {
                mainHandler(exchange.getRequestURI().getPath(), exchange.getRequestMethod(), exchange);
            });

            int shutdownDelay = Integer.parseInt(properties.getProperty("server.shutdownTimeout", "5"));
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                if (server != null) {
                    LOG.warn("Shutting down server...");
                    server.stop(shutdownDelay);
                    LOG.info("Server stopped.");
                }
            }));

            server.start();
            LOG.info("Server started on {}:{}", host, port);

        } catch (IOException err) {
            LOG.error("Failed to start server: {}", err.getMessage());
            System.exit(1);
        } catch (NumberFormatException err) {
            LOG.error("Invalid port or backlog number: {}", err.getMessage());
            System.exit(1);
        }
    }

    private static void mainHandler(String path, String method, HttpExchange exchange) {
        Route route = null;
        Method handler = null;
        for (Map.Entry<Route, Method> entry : handlers.entrySet()) {
            Route r = entry.getKey(); Method m = entry.getValue();
            if (path.equals(r.path()) && method.equals(r.method())) {
                route = r;
                handler = m;
                break;
            }
        }

        HTTPResult.Builder resultBuilder = new HTTPResult.Builder();

        if (route == null || handler == null) {
            if (!path.startsWith("@")) {
                mainHandler("@404", method, exchange);
                return;
            } else {
                resultBuilder.resultCode(404);
                resultBuilder.data("Not Found");
            }
        } else {
            try {
                Object result = handler.invoke(null);
                if (result instanceof HTTPResult httpResult) {
                    resultBuilder.from(httpResult);
                } else {
                    resultBuilder.data(result.toString());
                }
            } catch (IllegalAccessException | InvocationTargetException err) {
                LOG.error("Failed to invoke method `{}`: {}", handler.getName(), err.getMessage());
                resultBuilder.data("");
                resultBuilder.resultCode(500);
            }
        }

        HTTPResult result = resultBuilder.build();
        try {
            exchange.getResponseHeaders().add("content-type", result.getContentType());
            exchange.getResponseHeaders().add("server", properties.getProperty("server.headers.server", "nnnlib"));
            result.getHeaders().forEach((String key, String value) -> exchange.getResponseHeaders().add(key, value));
            properties.forEach((Object k, Object v) -> {
                String key = (String) k; String value = (String) v;
                if (key.startsWith("server.headers.")) {
                    key = key.substring("server.headers.".length());
                    if (exchange.getResponseHeaders().getOrDefault(key, null) != null) return;
                    exchange.getResponseHeaders().add(key, value);
                    LOG.debug("Add header: {}: {}", key, value);
                }
            });
            exchange.sendResponseHeaders(result.getResultCode(), result.getData().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(result.getData());
            }
        } catch (IOException err) {
            LOG.error("IO error while sending response for {}: {}", path, err.getMessage());
        }

        LOG.info("{} {} {} - {}",
                exchange.getRequestMethod().toUpperCase(), exchange.getRequestURI().getPath(),
                result.getResultCode(), exchange.getRemoteAddress().getAddress().getHostAddress());
    }
}
