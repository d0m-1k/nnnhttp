package pro.nnnteam.httplib;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.nnnteam.httplib.annotation.Route;
import pro.nnnteam.httplib.annotation.StartEntry;

import java.io.*;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.CodeSource;
import java.util.HashMap;
import java.util.Properties;

public class Main {
    private static final Logger LOG = LoggerFactory.getLogger(Main.class);
    private static final String CONFIG_FILE = "nnnhttp.properties";
    private static HashMap<Route, Method> handlers = new HashMap<>();

    private static boolean isRunningFromJar() {
        CodeSource source = Main.class.getProtectionDomain().getCodeSource();
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
            if (is == null) {
                throw new RuntimeException("Config file not found in classpath: " + resourceName);
            }
            props.load(is);
        } catch (IOException e) {
            throw new RuntimeException("Config file load error: " + resourceName, e);
        }
        return props;
    }

    private static Class<?> findMainClass(Properties props) {
        String mainClass = props.getProperty("mainClass", null);
        LOG.debug("mainClass = {}", mainClass);

        if (mainClass == null) {
            // TODO: Поиск класса вручную
            return null;
        }

        if (mainClass.isEmpty()) {
            LOG.debug("mainClass is empty");
            return null;
        }

        try {
            Class<?> clazz = Class.forName(mainClass);
            if (clazz.isAnnotationPresent(StartEntry.class)) {
                LOG.debug("mainClass annotated @StartEntry");
                return clazz;
            }
            LOG.debug("mainClass NOT annotated @StartEntry");
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

    public static void main(String[] args) {
        Properties props = loadProperties(CONFIG_FILE);
        Class<?> mainClass = findMainClass(props);
        if (mainClass == null) {
            LOG.error("Cannot find main class.");
            throw new IllegalStateException("Main class not found");
        }
        registerRouteHandlers(mainClass);

        handlers.forEach((Route route, Method handler) -> {
            LOG.info("path=\"{}\" method={} handler=<Method name={} class={}>",
                    route.path(), route.method(),
                    handler.getName(), handler.getDeclaringClass().getName());
        });
    }
}
