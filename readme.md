# WP Audit Files Command

A WP-CLI command that scans PHP files in your WordPress themes and plugins,
sends them in chunks to the Google Gemini API for analysis (checking for
potential malware, security vulnerabilities, etc.), and reports the findings.

**Disclaimer:** This tool uses a generative AI model (Google Gemini).
The analysis provided is not guaranteed to be exhaustive or perfectly accurate.
It should be used as *one part* of a comprehensive security audit, not as a
replacement for manual code review or professional security services. Use of
the Google Gemini API may incur costs and is subject to Google's terms of
service and rate limits.

## Requirements

*   WP-CLI version 0.25 or later.
*   PHP 7.4 or later.
*   Composer (used internally by `wp package install`).
*   A Google Gemini API Key.

## Installation

Ensure you have WP-CLI installed. Then, install the package directly from GitHub:

```bash
wp package install git@github.com:austinginder/wp-audit-files.git
```

Or using HTTPS:

```bash
wp package install https://github.com/austinginder/wp-audit-files.git
```

WP-CLI will handle downloading the package and making the `wp audit-files` command available.

## Configuration

You need to provide your [Google Gemini API key](https://aistudio.google.com/app/apikey) in one of two ways:

1. Environment Variable (Recommended): Set the `GEMINI_API_KEY` environment variable before running the command. 
    
    ```bash
    export GEMINI_API_KEY="YOUR_API_KEY_HERE"
    wp audit-files
    ```

2. Command-Line Flag: Use the --api-key flag with each command execution.

    ```bash
    wp audit-files --api-key=YOUR_API_KEY_HERE
    ```

## Usage

```bash
wp audit-files [--api-key=<key>] [--timeout=<seconds>] [--themes=<themes>] [--plugins=<plugins>] [--skip-api-call]
```

### Options:

- `--api-key=<key>`: Your Google Gemini API Key (overrides environment variable).
- `--timeout=<seconds>`: Timeout for each API request (default: 300).
- `--themes=<themes>`: Comma-separated list of theme slugs (directory names) to scan. If used, only specified themes/plugins are scanned.
- `--plugins=<plugins>`: Comma-separated list of plugin slugs (directory names) to scan. If used, only specified themes/plugins are scanned.
- `[--skip-api-call]`: Find files and calculate chunks, but do not call the Gemini API. Useful for estimating workload or debugging file discovery.

Examples:

```bash
# Scan ALL themes and plugins (requires GEMINI_API_KEY env var)
wp audit-files

# Scan ALL themes and plugins, providing API key via flag
wp audit-files --api-key=YOUR_API_KEY_HERE

# Scan only the 'twentytwentyfour' theme and the 'akismet' plugin
wp audit-files --themes=twentytwentyfour --plugins=akismet --api-key=YOUR_KEY

# See how many files/chunks would be processed without calling the API
wp audit-files --skip-api-call
```

**Output**

The command will:

1. Log its progress (finding files, creating chunks, calling API).
2. Display a table of potential issues found (sorted by severity: High > Medium > Low > Info).
3. Save the full list of issues (including code snippets if provided by the API) to a file named `all-issues.json` in the directory where you run the command.


## License

MIT License
