# encoding: utf-8

require 'csv'
require 'ffi'
require 'fileutils'
require 'find'
require 'nokogiri'
require 'uri'
require 'tempfile'
require 'typhoeus'
require 'yaml'

class URI::Generic
  def <=>(other)
    to_s <=> other.to_s
  end
end

module Wcrawl
  module Refinements
    refine NilClass do
      def empty?
        true
      end
    end

    refine String do
      def empty?
        strip == ''
      end

      def dirname
        (i = rindex('/')) ? self[0..i] : self
      end

      def html_encode(chars)
        gsub(Regexp.new("[#{chars}]")) {|m| '%%%02x' % m.ord }
      end
    end

    refine Typhoeus::Response do
      def content_type
        make_string(headers_hash["Content-Type"])
      end

      def location
        make_string(headers_hash["Location"])
      end

      private

      def make_string(val)
        val.nil? ? '' : val.kind_of?(Array) ? val.join('; ') : val
      end
    end

    refine URI::Generic do
      def dirname
        return nil if not is_a?(URI::HTTPS) and not is_a?(URI::HTTP)

        uri = clone
        uri.user = uri.password = uri.query = uri.fragment = nil
        uri.path = uri.path.dirname
        uri.to_s
      end
    end
  end

  using Refinements

  class Utility
    def Utility.is_windows?
      RUBY_PLATFORM =~ /mingw/
    end
  end

  # a broken/failed link, including details about the error
  class InvalidURI
    attr_reader :uri, :redirects_to, :pages_from, :reason
    attr_accessor :suspect

    InvalidURI::General_error = '0'
    InvalidURI::Page_has_moved = '1'
    InvalidURI::Not_found = '2'
    InvalidURI::Other_uri = '3'
    InvalidURI::Bad_response = '4'
    InvalidURI::Timeout = '5'
    InvalidURI::Conn_dropped = '6'
    InvalidURI::General_redirect = '7'

    def initialize(page, reason, extra = '')
      @uri = page.uri
      @pages_from = page.pages_from
      @redirects_to = page.redirects_to
      @reason = reason
      @extra = extra
      @suspect = false
    end

    # record a page that contains this link
    def add_page_from(page)
      @pages_from << page unless @pages_from.include?(page)
    end

    def to_a
      [@uri, @redirects_to, *@pages_from, @reason, @extra]
    end

    def error_message
      case @reason
      when InvalidURI::General_error then "error for #{@uri}: #{@extra}"
      when InvalidURI::Page_has_moved then "resource has moved: #{@uri} has moved to #{@extra}"
      when InvalidURI::Not_found then "not found: #{@uri}"
      when InvalidURI::Other_uri then "another uri: #{@uri} is also at #{@redirects_to} (code #{@extra})"
      when InvalidURI::Bad_response then "bad http response for #{@uri}: #{@extra}"
      when InvalidURI::Timeout then "timed out: #{@uri}"
      when InvalidURI::Conn_dropped then "connection to #{@uri} was dropped too many times"
      when InvalidURI::General_redirect then "#{@extra}: #{@uri} redirects to #{@redirects_to}"
      end + "\n\t#{@pages_from.join("\n\t")}"
    end
  end

  # a link that is queued for processing
  class LinkToLoad
    attr_reader :uri, :base, :pages_from, :content, :content_type, :meta_refresh
    attr_accessor :queue, :redirects_to, :redirect_code, :opts, :suspect

    # get the proxy, if any, that sits between us and the outside world
    def LinkToLoad.find_proxy
      proxy = URI.parse('http://host/').find_proxy
      return nil if not proxy
      proxy = proxy.host, proxy.port, proxy.user, proxy.password
      if proxy[2]
        proxy[3] = URI.unescape(proxy[3])
        @@proxy_userpass[proxy[0]] = proxy[2..3]
      end
      proxy
    end

    # record the username and password for a given host
    def LinkToLoad.add_userpass(host, user, password)
      @@userpass_list[host] = [user, URI.unescape(password)]
    end

    # prompt the user to enter the username and password for a given host or proxy
    def LinkToLoad.ask_for_userpass(type)
      $stderr.puts 'authentication required for ' + type
      $stderr.print 'username: '
      userpass = [gets.strip]
      return [] if userpass[0] == ''

      $stderr.print 'password: '
      userpass << gets.strip
    end

    @@HTTP_header = { 'User-Agent' => 'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-GB; rv:1.9.2.10) Gecko/20100914 Firefox/3.6.10' } # TODO: make this use the local os and language maybe?
    @@proxy_userpass = {}
    @@userpass_list = {}
    @@ruby_proxy = LinkToLoad.find_proxy

    def initialize(uri, pages_from, opts, queue)
      @uri = uri
      @base = uri.dirname
      @pages_from = (pages_from.kind_of?(Array) ? pages_from : [pages_from])
      @opts = opts
      @queue = queue
      @redirects_to = nil
      @redirect_code = nil
      @suspect = false
      @proxy = @@ruby_proxy
      @content = @content_type = @meta_refresh = nil
    end

    def init_with(coder)
      initialize(coder[:uri], coder[:pages_from], coder[:opts], coder[:queue])
      @redirects_to = coder[:redirects_to]
      @redirect_code = coder[:redirect_code]
      @suspect = coder[:suspect]
    end

    def encode_with(coder)
      coder[:uri] = @uri
      coder[:pages_from] = @pages_from
      coder[:opts] = @opts
      coder[:queue] = @queue
      coder[:redirects_to] = @redirects_to
      coder[:redirect_code] = @redirect_code
      coder[:suspect] = @suspect
    end

    # follow redirects to get to the final uri as necessary
    def actual_uri
      redirects_to or uri
    end

    # record a page that contains this link
    def add_page_from(page)
      pages_from << page unless pages_from.include?(page)
    end

    def to_a
      [uri, redirects_to, redirect_code, opts, suspect, *pages_from]
    end

    def to_s
      "to validate: #{uri} -> #{redirects_to} (code: #{redirect_code}) from [#{pages_from.join(', ')}]"
    end

    # get the proxy that applies to this particular link
    # on windows this requires dll interaction as it has richer proxy support and the proxy can be different for different links
    # on unix this is always a common proxy for all links that is provided via an environment variable
    def proxy
      return @proxy if @proxy
      return if not Utility.is_windows?

      handle = WinProxy.open(@@HTTP_header['User-Agent'], 1, nil, nil, 0)
      return @proxy if handle.null?

      options = WinProxy::Options.new
      options[:flags] = 1
      options[:auto_detect_flags] = 2
      options[:auto_logon] = 1
      info = WinProxy::Info.new
      res = WinProxy.get_proxy(handle, (uri.to_s + "\0").encode('utf-16le'), options, info)
      return @proxy if res == 0 # the call failed so return default proxy
      return unless info.proxy?

      puts "TODO: handle proxy bypass - #{info[:bypass].read_16bit_c_string}" unless info[:bypass].null?

      proxies = info[:proxy].read_16bit_c_string.strip.split(';').select {|p| not p.empty? }.map {|p| p.split(':') }
      @proxy = proxies[0]
      @proxy << '80' if @proxy.length == 1
      @proxy += proxy_userpass(proxies.map {|p| p[0] })

      WinProxy.free(info[:proxy])
      WinProxy.free(info[:bypass]) unless info[:bypass].null?

      @proxy
    end

    # validates self and searches for new pages to validate
    def validate(hydra, &on_complete)
      raise 'link has no queue to use' if not @queue

      puts "querying #{uri}" if @opts[:verbose]

      tries = 0

      begin
  #			request = Typhoeus::Request.new(uri.to_s, method: (@opts[:duplicate] ? :get : :method), auth_method: :auto, proxy_auth_method: :auto)
        opts = {
          headers: @@HTTP_header.merge(@opts[:duplicate] ? {} : { 'Accept' => 'text/html,application/xhtml+xml,application/xml,text/css,text/javascript' }),
        }

        # set up the proxy and proxy auth on the request if necessary
        proxy = self.proxy
        if proxy
          puts "using proxy #{proxy[2]}:#{proxy[3]}@#{proxy[0]}:#{proxy[1]}" if @opts[:verbose]
          opts.proxy = "http://#{proxy[0]}:#{proxy[1]}"
          if not proxy[2].empty?
            opts.proxy_username, opts.proxy_password = proxy[2], proxy[3]
          elsif @@userpass_list[:proxy]
            opts.proxy_username, opts.proxy_password = @@userpass_list[:proxy]
          end
        end

        # set up the auth on the request if necessary
        if uri.userinfo
          opts.username = uri.user
          opts.password = uri.password
        elsif @@userpass_list[uri.host]
          opts.username, opts.password = @@userpass_list[uri.host]
        end

        request = Typhoeus::Request.new(uri.to_s, opts)

        request.on_complete {|response|
          puts 'processing response from ' + uri.to_s if @opts[:verbose]

          if response.code == 401 or response.code == 407
            # the request requires authentication so ask the user for username and password
            # XXX there's a race here between setting userpass_list, queuing the request, and then an intervening request checking the unconfirmed userpass at the code above
            host = (response.code == 401 ? uri.host : :proxy)
            puts 'asking for ' + uri.to_s
            userpass = LinkToLoad.ask_for_userpass((host == :proxy ? 'proxy for ' :  '') + uri.to_s)
            if userpass.empty?
              @@userpass_list[host] = false
              process_response(response)
            else
              @@userpass_list[host] = userpass
              if host == :proxy
                $stderr.puts "setting proxy auth: #{userpass}"
                request.proxy_username, request.proxy_password = userpass
              else
                request.username, request.password = userpass
              end
              hydra.queue(request)
            end
          else
            process_response(response)
          end

          on_complete
        }

        hydra.queue(request)
      rescue OpenURI::HTTPError
        @queue.invalidate(InvalidURI::General_error, msg: "#{$!.class} - #{$!}")
      rescue Timeout
        tries += 1
        retry unless tries > 2
        @queue.invalidate(InvalidURI::Timeout)
      end
    end

    private

    # handle the response from the link request
    def process_response(response)
      content = response.body
      content_type = response.content_type
      if not content.empty? and content_type['html']
        content.force_encoding('iso-8859-1') # all bytes are valid in iso-859-1, so this ensures the next line never throws an encoding exception, yet still allows it to correctly match charset
        content.force_encoding($1) if content_type =~ /charset=([^;]+)/i or content =~ /<meta[^>]+charset=["']?([^;"'>]+)/i
      end

      if response.code == 0
        return @queue.invalidate(self, InvalidURI::Bad_response)
      elsif response.code == 301
        return @queue.invalidate(self, InvalidURI::Page_has_moved, parse_uri(response.location, base, uri))
      elsif response.code == 404
        # check for meta refreshes and javascript refreshes
        content.each_line {|line|
          uri = (match_meta_refresh(line, base, uri) or match_javascript_refresh(line))
          return @queue.invalidate(self, InvalidURI::Page_has_moved, uri) if uri
        } if not content.empty? and content_type['html']
        return @queue.invalidate(self, InvalidURI::Not_found)
      elsif response.code == 406
        # link is valid but not of a type we care about
        return
      elsif not response.success? and response.code != 302 and response.code != 303
        return @queue.invalidate(self, ((300..399) === response.code ? InvalidURI::General_redirect : InvalidURI::General_error), ((300..399) === response.code ? '' : "#{response.code} - ") + (response.status_message ? response.status_message.downcase : ''))
      end

      # search through the content for more links if doing recursive processing
      if opts[:recurse]
        if content_type['html']
          parse_html(content)
        elsif content_type['css']
          parse_css(content)
        elsif content_type['javascript']
          parse_javascript(content)
        end
      end

      # save the content if asked to
      duplicate(content_type, content) if @opts[:duplicate] and response.success? and LinkToLoad.within_root?(uri)

      if response.code == 302 or response.code == 303
        # gotten a temporary redirect code, so set a redirect for the page, invalidate it, and add a new entry for the new uri onto the queue
        new_uri = parse_uri(response.location, base, uri)
        within_root = LinkToLoad.within_root?(new_uri)
        redirects_to = new_uri
        redirect_code = response.code
        @queue.add_uri(new_uri, uri, within_root) if not @opts[:duplicate] or within_root
        @queue.invalidate(self, InvalidURI::Other_uri, redirect_code)
      elsif meta_refresh
        @queue.invalidate(self, InvalidURI::Page_has_moved, meta_refresh)
      end
    end

    def parse_html(content)
      html = Nokogiri.parse(content)

      # handle any meta refreshes
      html.xpath('//meta[@http-equiv="refresh"]/@content').each {|attr|
        @meta_refresh = parse_uri($1.strip, base, uri) if attr.content.strip =~ /url=(.+)/i
      } unless meta_refresh

      # grab all links and add them to the queue
      html.xpath('//@src | //@href').each {|attr|
        new_uri = parse_uri(attr.content.strip, base, uri)
        within_root = LinkToLoad.within_root?(new_uri)
        @queue.add_uri(new_uri, uri, within_root) if not @opts[:duplicate] or within_root
      }
    end

    def parse_css(content)
      within_script = within_comment = false
      content.each_line {|line|
        # check we aren't in a comment
        line, comments, within_comment = LinkToLoad.strip_invalid_data(line, within_comment, '/*', '*/') unless @opts[:check_comments]

        # XXX need to process escapes and do much better matching. see http://www.w3.org/TR/CSS21/syndata.html
        while line =~ /url\(\s*(["']?)([^)"']+)\1\s*\)/i
          new_uri = parse_uri($2, base, uri)
          @queue.add_uri(new_uri, uri, false) if not @opts[:duplicate] or LinkToLoad.within_root?(new_uri)
          line.sub!('url(', '')
        end
      }
    end

    # XXX causes a huge spike in memory use. very dodgy and wrong anyway
    def parse_javascript(content)
      i = 0
      while m = content.match(/(['"])(.*?[^\\])\1/, i)
        str = $2 # TODO unescape this string, eg. \\ -> \, \" -> "
        new_uri = nil
        begin
          if str.start_with?('http:') or str.start_with?('https:')
            new_uri = URI.parse(str)
          elsif str.include?('/') or str =~ /\.[a-z0-9]{1,8}$/
            new_uri = uri.merge(str)
          end

          if new_uri
            within_root = LinkToLoad.within_root?(new_uri)
            if not @opts[:duplicate] or within_root
              link = @queue.add_uri(new_uri, uri, within_root)
              link.suspect = true if link
            end
          end
        rescue URI::InvalidURIError
        end
        i = m.end(0)
      end
    end

    # save the content of the link, attempting to replace the links in the content to local references
    def duplicate(content_type, content)
      # TODO process CSS as well
      if content_type['html']
        Nokogiri.parse(content).search('@src', '@href').each {|attr|
          new_uri = parse_uri(attr.content.strip, base, uri)
          attr.content = uri_to_filename(new_uri.route_from(uri)).gsub(' ', '%20') if LinkToLoad.within_root?(new_uri)
        }
      end

      filename = uri_to_filename(uri)

      # create a local directory structure to match the site structure as necessary
      dir = nil
      filename.dirname.split('/').each {|subdir|
        dir = (dir ? File.join(dir, subdir) : subdir)
        if not File.exist?(dir)
          FileUtils.mkdir(dir)
        elsif File.file?(dir) # a page may already exist with the same name as the directory we want to create...
          temp = Tempfile.new('', '.')
          temp.close
          FileUtils.mv(dir, temp.path)
          FileUtils.mkdir(dir)
          FileUtils.mv(temp.path, File.join(dir, 'index.html'))
        end
      }

      File.open(filename, 'wb') {|f| f.write(content) }
    end

    # XXX this hasn't been tested thoroughly. most likely does the wrong thing for at least some inputs
    # TODO should maintain a table of uri -> path mappings for anything that gets changed or truncated so that
    # we can choose unique paths when there is a collision. then all uris will be mapped uniquely and correctly
    def uri_to_filename(uri, abspath = false)
      filename = File.join($aliases[0], (uri.path[-1] == '/' ? uri.path + 'index.html' : uri.path).gsub(/[:*?"<>|]/, '_'))
      filename = File.join(Dir.pwd, filename) if abspath
      filename = File.join(filename, 'index.html') if File.directory?(filename)
      filename += "_#{uri.query.gsub(/[:*?"<>|\/\\]/, '_')}" if uri.query

      # windows is stupid and call only handle paths <= 259 chars in length...
      # silently truncating causes potential problems but it's good enough for now
      filename = filename[0..258] if Utility.is_windows? and filename.length > 259

      filename
    end

    # library to interface with the windows proxy system
    module WinProxy
      extend FFI::Library

      class Info < FFI::Struct
        Info::No_proxy = 1		# no proxy is necessary for the given address
        Info::Named_proxy = 3	# a proxy is necessary and has been supplied

        layout :type, :ulong,
               :proxy, :pointer,
             :bypass, :pointer

        def proxy?
          self[:type] == Named_proxy and not self[:proxy].null?
        end
      end

      class Options < FFI::Struct
        layout :flags, :ulong,
               :auto_detect_flags, :ulong,
             :config_url, :pointer,
             :preserved, :pointer,
             :lreserved, :ulong,
             :auto_logon, :int
      end

      class FFI::Pointer
        def read_16bit_c_string
          i = 0
          str = ''
          until (c = get_bytes(i, 2)) == "\0\0"
            str += c.force_encoding('utf-16le')
            i += 2
          end
          str.encode('utf-8')
        end
      end

      if Utility.is_windows?
        ffi_lib 'kernel32.dll'
        ffi_convention :stdcall
        attach_function :free, 'GlobalFree', [:pointer], :pointer

        ffi_lib 'winhttp.dll'
        ffi_convention :stdcall
        attach_function :open, 'WinHttpOpen', [:string, :ulong, :string, :string, :ulong], :pointer
        attach_function :get_proxy, 'WinHttpGetProxyForUrl', [:pointer, :pointer, :pointer, :pointer], :int
      end
    end

    # get or prompt for a given proxy's username and password
    def proxy_userpass(proxies = [proxy[0]])
      proxies = [proxies] if proxies.class != Array
      proxies.map! {|p| p.downcase }
      userpass = (@@proxy_userpass[proxies[0]] || LinkToLoad.ask_for_userpass('proxy'))
      proxies.each {|p| @@proxy_userpass[p] = userpass }
      userpass
    end

    # strip out data that is contained between a start tag and an end tag
    # this is useful for removing comments in css and other unwanted content
    def LinkToLoad.strip_invalid_data(line, is_within, start_tag, end_tag)
      start_match = LinkToLoad.do_match(line, start_tag)
      end_match = LinkToLoad.do_match(line, end_tag)
      return ['', line, true] if is_within and not end_match

      # strip the data up to the first end tag when it comes before a start tag
      removed = ''
      if end_match and is_within and (not start_match or end_match[:pos] < start_match[:pos])
        removed = line[0...end_match[:pos]] + "\n"
        line = (line[end_match[:end_pos]..-1] || '')
        is_within = false
      end

      # strip data from a start tag up to an end tag or the end of the line, repeating until all matches are gone
      while start_match = LinkToLoad.do_match(line, start_tag)
        start = (line[0...start_match[:pos]] || '')
        end_match = LinkToLoad.do_match(line, end_tag)
        if end_match
          removed += line[start_match[:end_pos]...end_match[:pos]] + "\n"
          last = (line[end_match[:end_pos]..-1] || '')
          is_within = false
        else
          removed += line[start_match[:end_pos]...-1] + "\n"
          last = ''
          is_within = true
        end
        line = start + last
      end

      [line, removed, is_within]
    end

    # match a string or regexp against a string and return the match start and end indexes
    def LinkToLoad.do_match(line, match)
      pos = line.index(match)
      return nil if not pos
      { pos: pos, end_pos: pos + (match.class == Regexp ? $&.length : match.length) }
    end

    def parse_uri(uri, base, page_from)
#puts page_from.to_s + ': ' + uri + ' (' + base + ')' if uri != '' and not uri.start_with?(/https:\/\/www.slq.qld.gov.au|\/|\?|#/)
      # convert any character entities before starting
      uri = uri.strip.gsub('&quot;', '"').gsub('&apos;', '\'').gsub('&lt;', '<').gsub('&rt;', '>').gsub(/&(\d+);/) { $1.to_i.chr }.gsub(/&x([0-9a-z]+);/i) { $1.to_i(16).chr }.gsub('&amp;', '&')

      # strip the anchor, if any, keeping the query, if any :)
      if anchor = uri.index('#')
        query = uri.index('?')
        query = uri[query..-1] if query and anchor < query
        uri = uri[0...anchor]
        uri += query if query.class == String
      end

      # can't use default regexp because the uri might be partly escaped, so need to exclude % as well
      new_uri = URI::Parser.new.escape(uri, Regexp.new("[^#{URI::PATTERN::UNRESERVED}#{URI::PATTERN::RESERVED}%]"))
      if new_uri != uri and uri !~ /^(mailto|javascript)\:/i
        puts "improperly escaped link '#{uri}' in #{page_from}" if @opts[:verbose] and LinkToLoad.within_root?(page_from)
        uri = new_uri
      end

      begin
        if uri =~ /^([a-z]+\:|\/\/)/i
          # uri is fully qualified
          if $1 == '//' or $1 == 'http:' or $1 == 'https:'
            new_uri = uri
            new_uri += 'http:' if $1 == '//'
            new_uri += '/' if not (i = new_uri.rindex('/')) or i < $1.length + 2
            new_uri = URI.parse(reduce_path(new_uri))
            new_uri.host = $aliases[0] if $aliases.include?(new_uri.host)
          else
            return nil
          end
        elsif uri != '' and not uri.start_with?(/[a-z][a-z0-9.+-]*:/i)
          if uri[0] == '/'
            # uri is absolute
            new_uri = page_from.clone
            new_uri.path = ''
            new_uri.query = nil
            # the uri might have a query in it so we need to reparse the whole thing
            new_uri = URI.parse(new_uri.to_s + uri)
            new_uri.path = reduce_path(new_uri.path)
          elsif uri[0] == '?'
            # uri is just a query
            new_uri = page_from.clone
            new_uri.query = uri[1..-1]
          else
            # uri is relative
            new_uri = URI.parse(base + uri)
            new_uri.path = reduce_path(new_uri.path)
          end

          if new_uri.path =~ /\/\.\./
            puts "too many '..' in link '#{uri}' in #{page_from}" if @opts[:verbose] and LinkToLoad.within_root?(page_from)
            new_uri.path.gsub!(/\/\.\./, '')
          end
        else
          return nil
        end

        raise URI::InvalidURIError if new_uri.host.empty? or new_uri.path.empty?
      rescue URI::InvalidComponentError, URI::InvalidURIError
        puts "invalid link '#{uri}' in #{page_from}" if @opts[:verbose] and LinkToLoad.within_root?(page_from)
        return nil
      end

      return new_uri
    end

    # determine whether the uri is contained within the starting root dir/link
    def LinkToLoad.within_root?(uri)
      return false if not uri
      $roots.each {|d| return true if uri.dirname&.start_with?(d) }
      false
    end

    def match_meta_refresh(line, base, page)
      if line =~ /<meta([^>]*)http-equiv=["']refresh([^>]*)>/i
        if $1 + $2 =~ /content=['"].*url=([^'"]+)/i
          return parse_uri($1, base, page)
        end
      end
      nil
    end

    # piss-poor matching but the alternative is complex and this is good enough for error pages
    def match_javascript_refresh(line)
      line =~ /window.location\s*=\s*(["'].*)$/i ? "#{$1.sub(/\/\/.*$/, "").sub(/\s*-->.*$/, "").sub(/\s*<\/script>.*$/, "")} [javascript]" : nil
    end

    def valid(string)
      string and string.strip != ""
    end

    # turn a href into an absolute path
    def make_path(base, href)
      return href if href[0] == '/'
      base + href
    end

    # reduce any '../', './', and '//' in a path or uri
    def reduce_path(path)
      if path =~ /^(https?:\/\/.+)(\/.*)/
        prefix = $1
        path = $2
        relative = false
      else
        prefix = nil
        relative = path[0] != '/'
      end

      while path.sub!(/\/*[^\/]+\/+\.\./, ''); end
      while path.sub!(/\/+\.\/+/, '/'); end
      path = path[2..-1] if path[0..1] == './'
      while path.sub!(/\/\//, '/'); end

      path = path[1..-1] if relative and path[0] == '/'
      path = prefix + path if prefix
      path
    end

    class Timeout < Exception
    end
  end

  # maintains the list of links to be processed
  class LinkQueue
    using Refinements 
  
    attr_reader :opts, :to_validate, :validated, :invalid, :queued

    def initialize(opts)
      @opts = opts
      @to_validate = {}
      @queued = {}
      @validated = {}
      @invalid = {}
      @hydra = Typhoeus::Hydra.new
    end

    def init_with(coder)
      initialize(coder[:opts])
      @to_validate = coder[:to_validate]
      @validated = coder[:validated]
      @invalid = coder[:invalid]
    end
  
    def encode_with(coder)
      coder[:opts] = @opts
      coder[:to_validate] = @to_validate.merge(@queued)
      coder[:validated] = @validated
      coder[:invalid] = @invalid
    end

    # add a link to be processed
    def add_uri(new_link, from = nil, recurse = true)
      return if not new_link

      uri = (new_link.class == LinkToLoad ? new_link.uri : new_link)
      link = to_validate[uri] || queued[uri] || validated[uri] || invalid[uri]

      if not link
        puts 'queueing ' + uri.to_s if @opts[:verbose]
        link = (new_link.class == LinkToLoad ? new_link : LinkToLoad.new(uri, from, @opts.merge({ recurse: recurse }), self))
        to_validate[uri] = link
      elsif from and not @opts[:duplicate]
        link.add_page_from from
      end

      link
    end

    def validate
      begin
        while queue_next; end
        @hydra.run
      end until @to_validate.empty?
    end

    # grab the next link off the list
    def queue_next
      begin
        link = to_validate.shift
        return if not link

        queued[link[0]] = link[1]

        link[1].validate(@hydra) { |error: nil|
          queued.delete(link[0])

          if error then invalidate(link[1], error[:type], error[:msg])
          else validated[link[0]] = link[1]
          end
        }
        link
      rescue Exception
        unshift(link)
        raise $!
      end
    end

    # move the given link off the main queue and onto the invalid queue
    def invalidate(link, *args)
      queued.delete(link.uri)

      if not link.suspect
        inv = InvalidURI.new(link, *args)
        invalid[inv.uri] = inv
      elsif @opts[:verbose]
        puts 'questionable link invalidated: ' + link.uri.to_s
      end
    end

    # put a link back onto the queue
    def unshift(link)
      if link
        validated.delete(link[0])
        to_validate[link[0]] = link[1]
      end
    end
  end
end
