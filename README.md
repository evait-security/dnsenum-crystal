# dnsenum-crystal

`dnsenum-crystal` is a modern, high-performance reimagining of the infamous `dnsenum` tool, rewritten from the ground up in Crystal. While the original `dnsenum` served its purpose, its reliance on Perl makes it feel increasingly outdated in today's development landscape.

This project aims to provide the same powerful DNS enumeration capabilities with the speed, type safety, and modern development experience that Crystal offers.

## Features (Planned/Current)

-   **Fast:** Leveraging Crystal's native compilation for blazing-fast execution.
-   **Modern:** Built with a contemporary language and ecosystem.
-   **Familiar:** Retains the core functionality and spirit of the original `dnsenum`.

## Usage

```bash
dnsenum [options] <domain>
```

**Options:**

*   `--dnsserver server`: Specify a DNS server to use for queries
*   `--enum`: Perform a full enumeration (A, NS, MX, Zone Transfer, Reverse Lookup, WHOIS)
*   `--noreverse`: Skip reverse DNS lookups
*   `--threads n`: Set the number of threads (default: 10)
*   `-v`, `--verbose`: Enable verbose mode
*   `-o file`, `--output file`: Specify the output file
*   `-h`, `--help`: Show this help message
*   `--version`: Show version information

**Example:**

```bash
dnsenum -v --threads 20 example.com
dnsenum example.com
```

## Installation

### Pre-Compiled

```bash
wget https://github.com/evait-security/dnsenum-crystal/releases/download/latest/dnsenum
chmod +x dnsenum

./dnsenum
```

### Build from source

```bash
# git clone repo
cd dnsenum-crystal
shards build
bin/dnsenum example.com
```