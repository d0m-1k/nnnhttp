package pro.nnnteam.httplib;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.nnnteam.httplib.annotation.*;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

public class HTTPMain {
    private static final Logger LOG = LoggerFactory.getLogger(HTTPMain.class);
    private static final String CONFIG_FILE = "nnnhttp.properties";

    private static final List<RouteInfo> routeInfos = new ArrayList<>();
    private static HttpServer server = null;
    private static Properties properties;
    private static Object controllerInstance;

    private static final ThreadLocal<Map<String, String>> currentPathParams = new ThreadLocal<>();

    private static class RouteInfo {
        final String pattern;
        final Method method;
        final List<String> paramNames;
        final List<String> segments;

        RouteInfo(Route route, Method method) {
            this.pattern = route.path();
            this.method = method;
            this.segments = Arrays.asList(pattern.split("/"));
            this.paramNames = new ArrayList<>();
            for (String seg : segments) {
                if (seg.startsWith("{") && seg.endsWith("}")) {
                    paramNames.add(seg.substring(1, seg.length() - 1));
                }
            }
        }

        Map<String, String> match(String path) {
            String[] pathSegments = path.split("/");
            if (pathSegments.length != segments.size()) return null;

            Map<String, String> params = new HashMap<>();
            for (int i = 0; i < segments.size(); i++) {
                String patternSeg = segments.get(i);
                String pathSeg = pathSegments[i];
                if (patternSeg.startsWith("{") && patternSeg.endsWith("}")) {
                    params.put(patternSeg.substring(1, patternSeg.length() - 1), pathSeg);
                } else if (!patternSeg.equals(pathSeg)) {
                    return null;
                }
            }
            return params;
        }
    }

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
            LOG.debug("mainClass is null, no automatic scan yet");
            return null;
        }

        if (mainClass.trim().isEmpty()) {
            LOG.debug("mainClass is empty");
            return null;
        }

        try {
            Class<?> clazz = Class.forName(mainClass.trim());
            if (clazz.isAnnotationPresent(StartEntry.class)) {
                return clazz;
            }
            LOG.debug("{} not annotated @StartEntry", clazz.getName());
        } catch (ClassNotFoundException ignored) {
            LOG.debug("Class not found: " + mainClass);
        }

        return null;
    }

    private static void registerRouteHandlers(Class<?> clazz) {
        for (Method method : clazz.getDeclaredMethods()) {
            Route route = method.getAnnotation(Route.class);
            if (route != null) {
                routeInfos.add(new RouteInfo(route, method));
                LOG.debug("Registered route {} -> {}", route.path(), method.getName());
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

    public static void main() {
        properties = loadProperties(CONFIG_FILE);
        Class<?> mainClass = findMainClass(properties);
        if (mainClass == null) {
            LOG.error("Cannot find main class.");
            throw new IllegalStateException("Main class not found");
        }

        try {
            controllerInstance = mainClass.getDeclaredConstructor().newInstance();
        } catch (InstantiationException | IllegalAccessException | NoSuchMethodException | InvocationTargetException e) {
            LOG.error("Failed to create instance of main class", e);
            throw new RuntimeException("Cannot instantiate main class", e);
        }

        registerRouteHandlers(mainClass);

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

            server.createContext("/", HTTPMain::handleRequest);

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

    private static void handleRequest(HttpExchange exchange) {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod().toUpperCase();

        RouteInfo matchedInfo = null;
        Map<String, String> pathParams = null;
        for (RouteInfo info : routeInfos) {
            Route route = info.method.getAnnotation(Route.class);
            if (!method.equalsIgnoreCase(route.method())) continue;

            Map<String, String> params = info.match(path);
            if (params != null) {
                matchedInfo = info;
                pathParams = params;
                break;
            }
        }

        HTTPResult.Builder resultBuilder = new HTTPResult.Builder();

        if (matchedInfo == null) {
            resultBuilder.resultCode(404).data("Not Found".getBytes(StandardCharsets.UTF_8));
        } else {
            currentPathParams.set(pathParams);
            try {
                invoke(resultBuilder, matchedInfo.method, exchange);
            } finally {
                currentPathParams.remove();
            }
        }

        HTTPResult result = resultBuilder.build();

        try {
            if (result.getContentType() != null) {
                exchange.getResponseHeaders().set("Content-Type", result.getContentType());
            }
            exchange.getResponseHeaders().set("Server", properties.getProperty("server.headers.server", "nnnlib"));
            result.getHeaders().forEach(exchange.getResponseHeaders()::set);

            properties.forEach((keyObj, valueObj) -> {
                String key = (String) keyObj;
                if (key.startsWith("server.headers.")) {
                    String headerName = key.substring("server.headers.".length());
                    if (!exchange.getResponseHeaders().containsKey(headerName)) {
                        exchange.getResponseHeaders().set(headerName, (String) valueObj);
                    }
                }
            });

            byte[] data = result.getData();
            if (data == null) data = new byte[0];
            exchange.sendResponseHeaders(result.getResultCode(), data.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(data);
            }
        } catch (IOException e) {
            LOG.error("IO error while sending response for {}: {}", path, e.getMessage());
        }

        LOG.info("{} {} {} - {}",
                exchange.getRequestMethod().toUpperCase(), path,
                result.getResultCode(), exchange.getRemoteAddress().getAddress().getHostAddress());
    }

    private static void invoke(HTTPResult.Builder resultBuilder, Method handler, HttpExchange exchange) {
        try {
            Object[] args = prepareArguments(handler, exchange);
            Object result = handler.invoke(controllerInstance, args);

            if (result instanceof HTTPResult httpResult) {
                resultBuilder.data(httpResult.getData())
                        .resultCode(httpResult.getResultCode())
                        .contentType(httpResult.getContentType());
                for (Map.Entry<String, String> entry : httpResult.getHeaders().entrySet()) {
                    resultBuilder.putHeader(entry.getKey(), entry.getValue());
                }
            } else {
                String str = result != null ? result.toString() : "";
                resultBuilder.data(str.getBytes(StandardCharsets.UTF_8));
            }
        } catch (IllegalAccessException | InvocationTargetException e) {
            LOG.error("Failed to invoke method `{}`: {}", handler.getName(), e.getMessage());
            resultBuilder.data("Internal Server Error".getBytes(StandardCharsets.UTF_8)).resultCode(500);
        } catch (IllegalArgumentException e) {
            LOG.error("Invalid arguments for method `{}`: {}", handler.getName(), e.getMessage());
            resultBuilder.data("Bad Request".getBytes(StandardCharsets.UTF_8)).resultCode(400);
        }
    }

    private static Object[] prepareArguments(Method handler, HttpExchange exchange) {
        Parameter[] parameters = handler.getParameters();
        Object[] args = new Object[parameters.length];

        for (int i = 0; i < parameters.length; i++) {
            Parameter param = parameters[i];
            Class<?> type = param.getType();

            if (type.equals(HttpExchange.class)) {
                args[i] = exchange;
                continue;
            }

            PathParam pathParam = param.getAnnotation(PathParam.class);
            if (pathParam != null) {
                String value = extractPathParam(exchange.getRequestURI().getPath(), pathParam.value());
                args[i] = convert(value, type);
                continue;
            }

            QueryParam queryParam = param.getAnnotation(QueryParam.class);
            if (queryParam != null) {
                String value = null;
                String query = exchange.getRequestURI().getQuery();
                if (query != null) {
                    value = extractQueryParam(query, queryParam.value());
                }
                if (value == null) value = queryParam.defaultValue();
                args[i] = convert(value, type);
                continue;
            }

            Body body = param.getAnnotation(Body.class);
            if (body != null) {
                try (InputStream is = exchange.getRequestBody()) {
                    String bodyString = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                    args[i] = convert(bodyString, type);
                } catch (IOException e) {
                    throw new IllegalArgumentException("Failed to read request body", e);
                }
                continue;
            }

            throw new IllegalArgumentException("Parameter " + param.getName() + " has no annotation");
        }
        return args;
    }

    private static String extractPathParam(String path, String name) {
        Map<String, String> params = currentPathParams.get();
        return params != null ? params.get(name) : null;
    }

    private static String extractQueryParam(String query, String name) {
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length > 0 && kv[0].equals(name)) {
                return kv.length > 1 ? kv[1] : "";
            }
        }
        return null;
    }

    private static Object convert(String value, Class<?> targetType) {
        if (value == null) return null;
        if (targetType.equals(String.class)) return value;
        if (targetType.equals(int.class) || targetType.equals(Integer.class)) return Integer.parseInt(value);
        if (targetType.equals(long.class) || targetType.equals(Long.class)) return Long.parseLong(value);
        if (targetType.equals(boolean.class) || targetType.equals(Boolean.class)) return Boolean.parseBoolean(value);
        if (targetType.equals(byte[].class)) return value.getBytes(StandardCharsets.UTF_8);
        throw new IllegalArgumentException("Unsupported parameter type: " + targetType);
    }
}