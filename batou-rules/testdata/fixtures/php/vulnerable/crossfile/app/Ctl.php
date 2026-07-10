<?php
// Importer/caller: reads the $_GET superglobal (taint source) and
// forwards it across the file boundary into App\Repo::find(), which
// reaches a SQL sink. Cross-file (Layer-4) taint: source here -> static
// call -> sink in Repo.php. Expected finding: BATOU-INTERPROC-SQL_QUERY
// (CWE-89) at the Repo::find($n) call line.
namespace App;

use App\Repo;

class Ctl {
    public function show() {
        $n = $_GET["n"];
        return Repo::find($n);
    }
}
