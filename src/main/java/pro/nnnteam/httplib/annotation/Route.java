package pro.nnnteam.httplib.annotation;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@Documented
public @interface Route {
    String path();
    String method() default "GET";
}
