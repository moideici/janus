package org.janus;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal JSON reader for the test vectors: objects become {@link Map}, arrays {@link List},
 * numbers {@link Long} (integers only), strings {@link String}, plus Boolean and null.
 */
final class Json {

    private final String s;
    private int pos;

    private Json(String s) {
        this.s = s;
    }

    static Object parse(String text) {
        Json j = new Json(text);
        Object v = j.value();
        j.skipWs();
        if (j.pos != j.s.length()) {
            throw j.error("trailing characters");
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Object o) {
        return (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    static List<Object> list(Object o) {
        return o == null ? List.of() : (List<Object>) o;
    }

    private IllegalArgumentException error(String msg) {
        return new IllegalArgumentException("JSON: " + msg + " at offset " + pos);
    }

    private void skipWs() {
        while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) {
            pos++;
        }
    }

    private Object value() {
        skipWs();
        if (pos >= s.length()) {
            throw error("unexpected end");
        }
        char c = s.charAt(pos);
        if (c == '{') {
            return object();
        }
        if (c == '[') {
            return array();
        }
        if (c == '"') {
            return string();
        }
        if (s.startsWith("true", pos)) {
            pos += 4;
            return Boolean.TRUE;
        }
        if (s.startsWith("false", pos)) {
            pos += 5;
            return Boolean.FALSE;
        }
        if (s.startsWith("null", pos)) {
            pos += 4;
            return null;
        }
        int start = pos;
        if (c == '-') {
            pos++;
        }
        while (pos < s.length() && Character.isDigit(s.charAt(pos))) {
            pos++;
        }
        if (start == pos) {
            throw error("unexpected character");
        }
        return Long.parseLong(s.substring(start, pos));
    }

    private Map<String, Object> object() {
        Map<String, Object> m = new LinkedHashMap<>();
        pos++;
        skipWs();
        if (s.charAt(pos) == '}') {
            pos++;
            return m;
        }
        while (true) {
            skipWs();
            String key = string();
            skipWs();
            expect(':');
            m.put(key, value());
            skipWs();
            if (s.charAt(pos) == ',') {
                pos++;
            } else {
                expect('}');
                return m;
            }
        }
    }

    private List<Object> array() {
        List<Object> a = new ArrayList<>();
        pos++;
        skipWs();
        if (s.charAt(pos) == ']') {
            pos++;
            return a;
        }
        while (true) {
            a.add(value());
            skipWs();
            if (s.charAt(pos) == ',') {
                pos++;
            } else {
                expect(']');
                return a;
            }
        }
    }

    private void expect(char c) {
        if (pos >= s.length() || s.charAt(pos) != c) {
            throw error("expected '" + c + "'");
        }
        pos++;
    }

    private String string() {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (pos >= s.length()) {
                throw error("unterminated string");
            }
            char c = s.charAt(pos++);
            if (c == '"') {
                return sb.toString();
            }
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            char e = s.charAt(pos++);
            switch (e) {
                case '"', '\\', '/' -> sb.append(e);
                case 'b' -> sb.append('\b');
                case 'f' -> sb.append('\f');
                case 'n' -> sb.append('\n');
                case 'r' -> sb.append('\r');
                case 't' -> sb.append('\t');
                case 'u' -> {
                    sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                    pos += 4;
                }
                default -> throw error("bad escape");
            }
        }
    }
}
