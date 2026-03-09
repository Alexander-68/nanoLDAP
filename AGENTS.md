NanoLDAP is a minimalistic, secure, and self-contained LDAP server designed for simple infrastructure deployments. It provides a read-only LDAP/LDAPS interface for service integrations and a secure, embedded HTTP/HTTPS web interface for user and group administration.

The primary design philosophy is zero-dependency deployment: a single statically linked binary containing all HTML, CSS, JavaScript, and database engines, requiring no external services or configuration files to run.

Initial technical specification is in the file "NanoLDAP Specification and Implementation Plan.md".

This app code uses Go version 1.26 or newer. Use new Go features, skill $go, do not care for compatibility with older Go versions. 

Extra tools available to agents on Windows and Linux platforms: Powershell 7.5, ripgrep 15.0. When external test/tool scripts are required, use PowerShell for cross-system compatibility. Use skill $pwsh when creating or debugging Powershell scripts.

Typical flow: review the task, if you find something unclear or inconsistent - ask me for confirmation before implementing code, implement code, update tests, run tests, document.
Maintain README.md file updated with description and functionality for user.
