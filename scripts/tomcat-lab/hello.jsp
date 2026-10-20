<%--
  靶场页面：验证 Java 内存马时用它确认
  1) 容器本身可用（未注入时应返回 normal）
  2) 注入成功后请求被 Filter 拦截（带正确 token 头时返回 filter 的 JSON）
  3) 卸载后恢复 normal
--%>
<%@ page contentType="application/json;charset=UTF-8" %>
<%
    out.print("{\"ok\":true,\"lab\":\"normal\"}");
%>
