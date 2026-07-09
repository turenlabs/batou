<?php
// Cross-file (Layer-4) PHP taint sink. The DAO method concatenates its
// argument straight into $db->query(...) — a leaf SQL sink. The taint
// arrives from Ctl.php via the static call Repo::find($n). Expected
// cross-file finding: BATOU-INTERPROC-SQL_QUERY (CWE-89) with its sink
// step in this file.
namespace App;

class Repo {
    public static function find($n) {
        global $db;
        return $db->query("SELECT * FROM users WHERE name = '" . $n . "'");
    }
}
