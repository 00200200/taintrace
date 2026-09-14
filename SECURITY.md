# Security Policy

## Reporting a security vulnerability

Please do not open a public GitHub issue for a vulnerability that could be
used to compromise a user, or for details about an undisclosed malicious
package.

Report security issues privately by emailing [yunaremaia@gmail.com](mailto:yunaremaia@gmail.com).
Include enough information to reproduce the issue, such as:

- the affected taintrace version or commit;
- the operating system and Python version;
- the command, lockfile format, or configuration involved; and
- a minimal reproduction or proof of concept, with secrets removed.

For a malicious dependency report, include the package name, version,
ecosystem, relevant registry URL, and the evidence that led to the report.
Do not install or execute a suspicious package solely to investigate it.

Please allow time for the maintainer to investigate and coordinate a fix
before publicly disclosing details.

## Supported versions

taintrace is currently in alpha. Security fixes are provided on the latest
release and the default branch when practical. Older releases may not receive
backported fixes, so update to the latest version before reporting an issue.
