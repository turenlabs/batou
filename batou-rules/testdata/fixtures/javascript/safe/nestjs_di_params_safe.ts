import { Controller, Get, Post, Body, Query } from '@nestjs/common';
import { exec } from 'child_process';

// NestJS DI params are seeded as request sources, but no user data reaches the
// command sink — constant commands and a fixed allowlist. Must NOT be flagged.
@Controller('safe')
export class SafeOpsController {
  @Post('ping')
  ping(@Body() { note }: { note: string }) {
    // SAFE: constant command; the seeded `note` taint never reaches exec
    exec('echo pong');
  }

  @Get('list')
  list(@Query() { which }: { which: string }) {
    // SAFE: command built entirely from a fixed allowlist, not from `which`
    const allowed: Record<string, string> = { a: '/tmp/a', b: '/tmp/b' };
    exec('ls ' + allowed['a']);
  }
}
