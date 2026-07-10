import { Controller, Get, Post, Body, Query, Param } from '@nestjs/common';
import { exec } from 'child_process';

// NestJS dependency-injection request surfaces flowing to a command sink.
// Destructured @Body()/@Query() params and bound-then-accessed @Body() are all
// user-controlled (CWE-78). Before seedJSParamBindings these bound nothing.
@Controller('ops')
export class OpsController {
  @Post('run')
  run(@Body() { cmd }: { cmd: string }) {
    // VULN: destructured request body field reaches exec
    exec(cmd);
  }

  @Get('search')
  search(@Query() q: { term: string }) {
    // VULN: whole-query DI param accessed and passed to exec
    exec('grep ' + q.term);
  }

  @Get('ls/:dir')
  list(@Param() { dir }: { dir: string }) {
    // VULN: destructured route param reaches exec
    exec('ls ' + dir);
  }
}
