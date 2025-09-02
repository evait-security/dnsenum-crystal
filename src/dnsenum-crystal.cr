require "option_parser"
require "openssl"
require "dns"
require "socket"

module Dnsenum
  VERSION = "0.1.0"

  class CLI
    property dnsserver : String?
    property full_enum : Bool = false
    property noreverse : Bool = false
    property threads : Int32 = 10
    property verbose : Bool = false
    property output_file : String?
    property domain : String?

    def initialize
      parse_options
    end

    def parse_options
      OptionParser.parse do |parser|
        parser.banner = "Usage: dnsenum-crystal [options] <domain>"

        parser.on("--dnsserver server", "Specify a DNS server to use for queries") do |server|
          self.dnsserver = server
        end

        parser.on("--enum", "Perform a full enumeration") do
          self.full_enum = true
        end

        parser.on("--noreverse", "Skip reverse DNS lookups") do
          self.noreverse = true
        end

        parser.on("--threads n", "Set the number of threads") do |n|
          self.threads = n.to_i
        end

        parser.on("-v", "--verbose", "Enable verbose mode") do
          self.verbose = true
        end

        parser.on("-o file", "--output file", "Specify the output file") do |file|
          self.output_file = file
        end

        parser.on("-h", "--help", "Show this help") do
          puts parser
          exit
        end

        parser.on("--version", "Show version") do
          puts "dnsenum-crystal #{VERSION}"
          exit
        end
      end

      if ARGV.empty?
        puts "Error: domain is required"
        exit 1
      else
        self.domain = ARGV[0]
      end
    end

    def run
      original_stdout = STDOUT
      if output_file = self.output_file
        begin
          file = File.open(output_file, "w")
          STDOUT.reopen(file)
        rescue ex
          puts "Error opening output file #{output_file}: #{ex.message}"
          return
        end
      end

      puts "DNS Enumeration for: #{domain}"
      if dnsserver = self.dnsserver
        puts "DNS Server: #{dnsserver}"
        begin
          # Resolve the hostname to an IP address
          addrinfos = Socket::Addrinfo.resolve(dnsserver, 53, Socket::Family::UNSPEC, Socket::Type::STREAM)
          if addrinfos.empty?
            puts "Error: Could not resolve IP for DNS server #{dnsserver}. Using default resolver."
          else
            resolved_ip = addrinfos.first.ip_address.address
            DNS.default_resolver = DNS::Resolver::UDP.new([resolved_ip])
          end
        rescue ex
          puts "Error resolving DNS server #{dnsserver}: #{ex.message}. Using default resolver."
        end
      end
      if verbose
        puts "Threads: #{threads}"
        puts "Verbose: #{verbose}"
        puts "Reverse lookup: #{!noreverse}"
      end
      puts "Output file: #{output_file}" if output_file

      resolver = DNSResolver.new(domain.not_nil!, threads, noreverse, verbose)

      if full_enum
        resolver.get_a_records
        ns_servers = resolver.get_ns_records
        resolver.get_mx_records
        resolver.perform_zone_transfer(ns_servers)
        resolver.perform_reverse_lookup unless noreverse
        resolver.perform_whois_lookup
      else # Default enumeration if --enum is not provided
        resolver.get_a_records
        resolver.get_ns_records
        resolver.get_mx_records
        resolver.perform_reverse_lookup unless noreverse
      end

      if output_file
        STDOUT.reopen(original_stdout)
        file.try &.close
      end
    end
  end

  class DNSResolver
    property domain : String
    property threads : Int32
    property noreverse : Bool
    property verbose : Bool

    def initialize(@domain, @threads, @noreverse, @verbose)
    end

    def get_a_records
      puts "\n--- A Records ---"
      begin
        responses = DNS.query(domain, [DNS::RecordType::A])
        if responses
          responses.each do |response|
            puts response.ip_address.address
          end
        end
      rescue ex
        puts "Error getting A records: #{ex.message}" if verbose
      end
    end

    def get_ns_records : Array(String)
      puts "\n--- NS Records ---"
      ns_servers = [] of String
      begin
        responses = DNS.query(domain, [DNS::RecordType::NS])
        if responses
          responses.each do |response|
            ns_server = response.name_server
            puts ns_server
            ns_servers << ns_server
          end
        end
      rescue ex
        puts "Error getting NS records: #{ex.message}" if verbose
      end
      ns_servers
    end

    def get_mx_records
      puts "\n--- MX Records ---"
      begin
        responses = DNS.query(domain, [DNS::RecordType::MX])
        if responses
          mx_records = responses.compact_map do |response|
            response.resource.as?(DNS::Resource::MX)
          end
          mx_records.sort_by(&.preference).each do |mx|
            puts "#{mx.exchange} (preference: #{mx.preference})"
          end
        end
      rescue ex
        puts "Error getting MX records: #{ex.message}" if verbose
      end
    end

    def perform_zone_transfer(ns_servers : Array(String))
      puts "\n--- Zone Transfer (AXFR) ---"
      ns_servers.each do |ns_server|
        puts "Attempting zone transfer from #{ns_server}..."
        begin
          # Temporarily set default resolver to system resolver for NS IP resolution
          original_resolver = DNS.default_resolver
          DNS.default_resolver = DNS::Resolver::System.new

          ns_ip_responses = DNS.query(ns_server, [DNS::RecordType::A])

          # Restore original resolver
          DNS.default_resolver = original_resolver
          if ns_ip_responses.empty?
            puts "Could not resolve IP for #{ns_server}. Skipping zone transfer." if verbose
            next
          end
          ns_ip = ns_ip_responses.first.ip_address.address
          puts "Resolved #{ns_server} to #{ns_ip}" if verbose

          begin
            socket = TCPSocket.new(ns_ip, 53)
            puts "Connected to #{ns_ip}:53" if verbose

            # Construct AXFR query
            query_id = Random.rand(65535).to_u16 # Random 16-bit ID
            question = DNS::Packet::Question.new(domain, 252_u16, DNS::ClassCode::Internet.value)
            packet = DNS::Packet.new(
              id: query_id,
              operation_code: DNS::OpCode::QUERY,
              recursion_desired: true,
              questions: [question]
            )

            query_bytes = packet.to_slice
            # Prepend length (2 bytes)
            length_io = IO::Memory.new
            length_io.write_bytes(query_bytes.size.to_u16, IO::ByteFormat::BigEndian)
            length_bytes = length_io.to_slice
            socket.write(length_bytes)
            socket.write(query_bytes)
            puts "Sent AXFR query for #{domain} to #{ns_ip}" if verbose

            loop do
              # Read 2-byte length
              length_bytes = Bytes.new(2)
              bytes_read = socket.read(length_bytes)
              break if bytes_read == 0 # Connection closed

              message_length = IO::Memory.new(length_bytes).read_bytes(UInt16, IO::ByteFormat::BigEndian)
              if message_length == 0
                puts "Received empty message length. Closing connection." if verbose
                break
              end

              # Read DNS message
              message_bytes = Bytes.new(message_length)
              socket.read_fully(message_bytes)

              # Parse DNS message
              begin
                response_packet = DNS::Packet.from_slice(message_bytes)
                response_packet.answers.each do |answer|
                  if answer.record_type == DNS::RecordType::MX
                    mx = answer.resource.as(DNS::Resource::MX)
                    puts "  #{answer.name} MX #{mx.exchange} (preference: #{mx.preference})"
                  else
                    puts "  #{answer.name} #{answer.record_type} #{answer.resource}"
                  end
                end
              rescue ex
                puts "Error parsing DNS response: #{ex.message}" if verbose
              end
            end
            socket.close
          rescue ex
            puts "Error connecting to #{ns_ip}:53: #{ex.message}" if verbose
          end
        rescue ex
          puts "Error resolving IP for #{ns_server}: #{ex.message}. Skipping zone transfer." if verbose
        end
      end
    end

    def perform_reverse_lookup
      return if noreverse

      puts "\n--- Reverse Lookup ---"
      begin
        responses = DNS.query(domain, [DNS::RecordType::A])
        if responses && !responses.empty?
          responses.each do |response|
            ip_address = response.ip_address # This is already a Socket::IPAddress object
            puts "Performing reverse lookup for #{ip_address.address}..." if verbose
            begin
              hostnames = DNS.reverse_lookup(ip_address)
              if hostnames && !hostnames.empty?
                hostnames.each do |hostname|
                  puts "  #{ip_address.address} -> #{hostname}"
                end
              else
                puts "  No hostname found for #{ip_address.address}" if verbose
              end
            rescue ex
              puts "Error performing reverse lookup for #{ip_address.address}: #{ex.message}" if verbose
            end
          end
        end
      rescue ex
        puts "Error getting A records for reverse lookup: #{ex.message}" if verbose
      end
    end

    def perform_whois_lookup
      puts "\n--- WHOIS Lookup ---"
      begin
        # Try to use the system's whois command first
        if `which whois 2>/dev/null`.strip.empty?
          puts "WHOIS command not found on system."
          puts "Attempting basic native WHOIS lookup..." if verbose
          # Basic native WHOIS lookup
          whois_server = "whois.iana.org"
          port = 43
          begin
            socket = TCPSocket.new(whois_server, port)
            socket.puts "#{domain}\r\n"
            response = socket.gets_to_end
            puts response
            socket.close
          rescue ex
            if verbose
              puts "Error performing native WHOIS lookup: #{ex.message}"
            else
              puts "Native WHOIS lookup failed. Check network connection or try installing 'whois' command."
            end
          end
        else
          # Use the system's whois command
          command = "whois #{domain}"
          puts "Running command: #{command}" if verbose
          output = `#{command}`
          puts output
        end
      rescue ex
        puts "Error performing WHOIS lookup: #{ex.message}"
      end
    end
  end

  CLI.new.run
end