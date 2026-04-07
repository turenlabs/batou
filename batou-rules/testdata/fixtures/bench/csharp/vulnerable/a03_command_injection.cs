// Source: CWE-78 - OS Command Injection via Process.Start in C#
// Expected: BATOU-INJ, TAINT
// OWASP: A03:2021 - Injection (Command Injection)

using System;
using System.Diagnostics;

namespace App
{
    class CommandRunner
    {
        public void RunCommand(string userInput)
        {
            var cmd = "ping -c 1 " + userInput;
            Process.Start("/bin/sh", "-c " + cmd);
        }

        static void Main(string[] args)
        {
            var runner = new CommandRunner();
            runner.RunCommand(args[0]);
        }
    }
}
