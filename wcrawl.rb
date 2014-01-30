#!/usr/bin/ruby
# encoding: utf-8

Resume_file = 'wcrawl_save.csv'
HTTP_header = { 'User-Agent' => 'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-GB; rv:1.9.2.10) Gecko/20100914 Firefox/3.6.10' } # TODO: make this use the local os and language maybe?

$queue = nil
$options = {}
$target = nil
$javascript = ''

def usage
	puts <<_EOU
usage:  link_check [-csv] [-t <num>] [-o dir] <uri>
        link_check [-cv] [-t <num>] -r

        -c: check within comment tags (<!-- comment -->)
        -d: download and save to the current local directory
        -o: match the validated urls against a local directory to discover orphaned pages
        -r: resume an interrupted scan
        -s: check just the first page (ie. not recursive)
        -v: be verbose (eg. warn on improperly escaped urls, etc.)
_EOU
	exit
end

while arg = ARGV.shift
	if arg[0] == '-'
		arg[1..-1].each_char {|char|
			case char
			when 'c' then $options[:check_comments] = true
			when 'd' then $options[:duplicate] = true
			when 'o' then $options[:orphans] = ARGV.shift
			when 'r' then $options[:resume] = true
			when 's' then $options[:single] = true
			when 'v' then $options[:verbose] = true
			else usage
			end
		}
    elsif not $target and not $options[:resume]
        $target = arg
		puts arg
    else usage
    end
end
usage if not $target and not $options[:resume]

$stderr.puts 'loading libraries: '
$stderr.print 'csv... '
require 'csv'
$stderr.puts 'done'
$stderr.print 'ffi... '
require 'ffi'
$stderr.puts 'done'
$stderr.print 'fileutils... '
require 'fileutils'
$stderr.puts 'done'
$stderr.print 'find... '
require 'find'
$stderr.puts 'done'
$stderr.print 'nokogiri... '
require 'nokogiri'
$stderr.puts 'done'
$stderr.print 'open-uri... '
require 'open-uri'
$stderr.puts 'done'
$stderr.print 'rbtree... '
require 'rbtree'
$stderr.puts 'done'
$stderr.print 'resolv... '
require 'resolv'
$stderr.puts 'done'
$stderr.print 'tempfile... '
require 'tempfile'
$stderr.puts 'done'
$stderr.print 'typhoeus... '
require 'typhoeus'
$stderr.puts 'done'
$stderr.puts 'libraries loaded'

def is_windows?
	RUBY_PLATFORM =~ /mingw/
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

	def InvalidURI.from_a(array)
		uri = URI.parse(array.shift)
		redirects_to = array.shift
		redirects_to = (redirects_to.empty? ? nil : URI.parse(redirects_to))
		extra = array.delete_at(-1)
		reason = array.delete_at(-1)
		pages_from = array.map {|uri| uri.empty? ? nil : URI.parse(uri) }.compact
		InvalidURI.new({uri: uri, pages_from: pages_from, redirects_to: redirects_to}, reason, extra)
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
	attr_accessor :redirects_to, :redirect_code, :recurse, :suspect

	def LinkToLoad.from_a(array)
		uri = URI.parse(array.shift)
		redirects_to = array.shift
		redirects_to = (redirects_to.empty? ? nil : URI.parse(redirects_to))
		redirect_code = array.shift
		redirect_code = (redirect_code.empty? ? nil : redirect_code.to_i)
		recurse = (array.shift == 'true')
		link = LinkToLoad.new(uri, array.map {|uri| URI.parse(uri) }, recurse, redirects_to, redirect_code)

		suspect = (array.shift == 'true')
		link.suspect = suspect

		link
	end

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

	@@proxy_userpass = {}
	@@userpass_list = {}
	@@ruby_proxy = LinkToLoad.find_proxy

	def initialize(uri, pages_from, recurse, redirects_to = nil, redirect_code = nil)
		@uri = uri
		@base = uri.dirname
		@pages_from = (pages_from.kind_of?(Array) ? pages_from : [pages_from])
		@recurse = recurse
		@redirects_to = redirects_to
		@redirect_code = redirect_code
		@suspect = false
		@proxy = @@ruby_proxy
		@content = @content_type = @meta_refresh = nil
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
		[uri, redirects_to, redirect_code, recurse, suspect, *pages_from]
	end

	def to_s
		"to validate: #{uri} -> #{redirects_to} (code: #{redirect_code}) from [#{pages_from.join(', ')}]"
	end

	# get the proxy that applies to this particular link
	# on windows this requires dll interaction as it has richer proxy support and the proxy can be different for different links
	# on unix this is always a common proxy for all links that is provided via an environment variable
	def proxy
		return @proxy if @proxy
		return if not is_windows?

		handle = WinProxy.open(HTTP_header['User-Agent'], 1, nil, nil, 0)
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
	def validate(hydra)
		return if uri.scheme == 'https' # XXX is this necessary now we've switched to typhoeus?

		puts "querying #{uri}" if $options[:verbose]

		tries = 0

		begin
#			request = Typhoeus::Request.new(uri.to_s, method: ($options[:duplicate] ? :get : :method), auth_method: :auto, proxy_auth_method: :auto)
			request = Typhoeus::Request.new(uri.to_s, auth_method: :auto, proxy_auth_method: :auto)
			request.headers = HTTP_header.clone
			request.headers.update({ 'Accept' => 'text/html,application/xhtml+xml,application/xml,text/css,text/javascript' }) if not $options[:duplicate]

			# set up the proxy and proxy auth on the request if necessary
			proxy = self.proxy
			if proxy
				puts "using proxy #{proxy[2]}:#{proxy[3]}@#{proxy[0]}:#{proxy[1]}" if $options[:verbose]
				request.proxy = "http://#{proxy[0]}:#{proxy[1]}"
				if not proxy[2].empty?
					request.proxy_username, request.proxy_password = proxy[2], proxy[3]
				elsif @@userpass_list[:proxy]
					request.proxy_username, request.proxy_password = @@userpass_list[:proxy]
				end
			end

			# set up the auth on the request if necessary
			if uri.userinfo
				request.username = uri.user
				request.password = uri.password
			elsif @@userpass_list[uri.host]
				request.username, request.password = @@userpass_list[uri.host]
			end

			request.on_complete {|response|
				puts 'processing response from ' + uri.to_s if $options[:verbose]

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
			}

			hydra.queue(request)
		rescue OpenURI::HTTPError
			$queue.invalidate(self, InvalidURI::General_error, "#{$!.class} - #{$!}")
		rescue Timeout
			tries += 1
			retry unless tries > 2
			$queue.invalidate(self, InvalidURI::Timeout)
		end
	end

	private

	# handle the response from the link request
	def process_response(response)
		@content = response.body
		@content_type = response.content_type
		if not content.empty? and content_type['html']
			content.force_encoding('iso-8859-1') # all bytes are valid in iso-859-1, so this ensures the next line never throws an encoding exception, yet still allows it to correctly match charset
			content.force_encoding($1) if content_type =~ /charset=([^;]+)/i or content =~ /<meta[^>]+charset=["']?([^;"'>]+)/i
		end

		if response.code == 0
			return $queue.invalidate(self, InvalidURI::Bad_response)
		elsif response.code == 301
			return $queue.invalidate(self, InvalidURI::Page_has_moved, parse_uri(response.location, base, uri))
		elsif response.code == 404
			# check for meta refreshes and javascript refreshes before leaving. yes, it happens...
			content.each_line {|line|
				uri = (match_meta_refresh(line, base, uri) or match_javascript_refresh(line))
				return $queue.invalidate(self, InvalidURI::Page_has_moved, uri) if uri
			} if not content.empty? and content_type['html']
			return $queue.invalidate(self, InvalidURI::Not_found)
		elsif response.code == 406
			# link is valid but not of a type we care about
			return
		elsif not response.success? and response.code != 302 and response.code != 303
			return $queue.invalidate(self, ((300..399) === response.code ? InvalidURI::General_redirect : InvalidURI::General_error), ((300..399) === response.code ? '' : "#{response.code} - ") + (response.status_message ? response.status_message.downcase : ''))
		end

		# search through the content for more links if doing recursive processing
		if recurse
			if content_type['html']
				parse_html
			elsif content_type['css']
				parse_css
			elsif content_type['javascript']
				parse_javascript
			end
		end

		# save the content if asked to
		duplicate if $options[:duplicate] and response.success? and LinkToLoad.within_root?(uri)

		if response.code == 302 or response.code == 303
			# gotten a temporary redirect code, so set a redirect for the page, invalidate it, and add a new entry for the new uri onto the queue
			new_uri = parse_uri(response.location, base, uri)
			within_root = LinkToLoad.within_root?(new_uri)
			redirects_to = new_uri
			redirect_code = response.code
			$queue.add_uri(new_uri, uri, within_root) if not $options[:duplicate] or within_root
			$queue.invalidate(self, InvalidURI::Other_uri, redirect_code)
		elsif meta_refresh
			$queue.invalidate(self, InvalidURI::Page_has_moved, meta_refresh)
		end
	end

	def parse_html
		html = Nokogiri.parse(content)

		# handle any meta refreshes (that should be bloody server redirects!)
		html.xpath('//meta[@http-equiv="refresh"]/@content').each {|attr|
			@meta_refresh = parse_uri($1.strip, base, uri) if attr.content.strip =~ /url=(.+)/i
		} unless meta_refresh

		# grab all links and add them to the queue
		html.xpath('//@src | //@href').each {|attr|
			new_uri = parse_uri(attr.content.strip, base, uri)
			within_root = LinkToLoad.within_root?(new_uri)
			$queue.add_uri(new_uri, uri, within_root) if not $options[:duplicate] or within_root
		}
	end

	def parse_css
		within_script = within_comment = false
		content.each_line {|line|
			# check we aren't in a comment
			line, comments, within_comment = LinkToLoad.strip_invalid_data(line, within_comment, '/*', '*/') unless $options[:check_comments]

			# XXX need to process escapes and do much better matching. see http://www.w3.org/TR/CSS21/syndata.html
			while line =~ /url\(\s*(["']?)([^)]+)\1\s*\)/i
				new_uri = parse_uri($2, base, uri)
				$queue.add_uri(new_uri, uri, false) if not $options[:duplicate] or LinkToLoad.within_root?(new_uri)
				line.sub!('url(', '')
			end
		}
	end

	# XXX causes a huge spike in memory use, leading to NoMemoryError exceptions. very dodgy and wrong anyway
	def parse_javascript(content = self.content)
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
					if not $options[:duplicate] or within_root
						link = $queue.add_uri(new_uri, uri, within_root)
						link.suspect = true if link
					end
				end
			rescue URI::InvalidURIError
			end
			i = m.end(0)
		end
		$javascript += content + "\n"
	end

	# save the content of the link, attempting to replace the links in the content to local references
	def duplicate
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
		filename = filename[0..258] if is_windows? and filename.length > 259

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

		ffi_lib 'kernel32.dll'
		ffi_convention :stdcall
		attach_function :free, 'GlobalFree', [:pointer], :pointer

		ffi_lib 'winhttp.dll'
		ffi_convention :stdcall
		attach_function :open, 'WinHttpOpen', [:string, :ulong, :string, :string, :ulong], :pointer
		attach_function :get_proxy, 'WinHttpGetProxyForUrl', [:pointer, :pointer, :pointer, :pointer], :int
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
		new_uri = URI.escape(uri, Regexp.new("[^#{URI::PATTERN::UNRESERVED}#{URI::PATTERN::RESERVED}%]"))
		if new_uri != uri and uri !~ /^(mailto|javascript)\:/i
			puts "improperly escaped link '#{uri}' in #{page_from}" if $options[:verbose] and LinkToLoad.within_root?(page_from)
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
			elsif uri != ''
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
					puts "too many '..' in link '#{uri}' in #{page_from}" if $options[:verbose] and LinkToLoad.within_root?(page_from)
					new_uri.path.gsub!(/\/\.\./, '')
				end
			else
				return nil
			end

			raise URI::InvalidURIError if new_uri.host.empty? or new_uri.path.empty?
		rescue URI::InvalidComponentError, URI::InvalidURIError
			puts "invalid link '#{uri}' in #{page_from}" if $options[:verbose] and LinkToLoad.within_root?(page_from)
			return nil
		end

		return new_uri
	end

	# determine whether the uri is contained within the starting root dir/link
	def LinkToLoad.within_root?(uri)
		return false if not uri
		$roots.each {|d| return true if uri.dirname.start_with?(d) }
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
	attr_reader :to_validate, :validated, :invalid

	def initialize(to_validate = RBTree.new, validated = RBTree.new, invalid = RBTree.new)
		@to_validate = to_validate
		@validated = validated
		@invalid = invalid
		@hydra = Typhoeus::Hydra.new
		@hydra.disable_memoization
	end

	# add a link to be processed
	def add_uri(new_link, from = nil, recursive = true)
		return if not new_link

		new_uri = (new_link.class == LinkToLoad ? new_link.uri : new_link)
		if from and not $options[:duplicate]
			if link = (to_validate[new_uri] || invalid[new_uri])
				link.add_page_from from
				return link
			end
		end

		if not validated.include?(new_uri) and not to_validate.include?(new_uri)
			puts 'queueing ' + new_uri.to_s if $options[:verbose]
			link = (new_link.class == LinkToLoad ? new_link : LinkToLoad.new(new_uri, from, $options[:single] ? false : recursive))
			to_validate[new_uri] = link
			return link
		end

		nil
	end

	def validate
		begin
			while validate_next; end
			@hydra.run
		end until @hydra.empty? and @to_validate.empty?
	end

	# grab the next link off the list
	def validate_next
		begin
			link = to_validate.shift
			return if not link
			validated[link[0]] = true
			link[1].validate(@hydra)
			link
		rescue Exception
			unshift(link)
			raise $!
		end
	end

	# move the given link off the main queue and onto the invalid queue
	def invalidate(link, *args)
		if not link.suspect
			inv = InvalidURI.new(link, *args)
			invalid[inv.uri] = inv
			puts 'questionable link invalidated: ' + link.uri.to_s
		elsif $options[:verbose]
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

class URI::HTTP
	def dirname
		uri = clone
		uri.user = uri.password = uri.query = uri.fragment = nil
		uri.path = uri.path.dirname
		uri.to_s
	end
end

class NilClass
	def empty?
		true
	end
end

class String
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

class Typhoeus::Hydra
	def length
		@running_requests + @queued_requests.length
	end

	def empty?
		length == 0
	end
end

class Typhoeus::Response
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

class URI::Generic
	def <=>(other)
		to_s <=> other.to_s
	end
end

if $options[:resume]
	validated = RBTree.new
	to_validate = RBTree.new
	invalid = RBTree.new

	# load the resume file
	begin
		CSV.foreach(Resume_file) {|uri|
			if not $target
				$target = URI.parse(uri.first)
			elsif uri.length == 1
				validated[URI.parse(uri.first)] = true
			elsif uri.length >= 3
				if uri[-1] =~ /^true|false$/i
					link = LinkToLoad.from_a(uri)
					to_validate[link.uri] = link
				else
					err = InvalidURI.from_a(uri)
					invalid[err.uri] = err
				end
			end
		}
		$queue = LinkQueue.new(to_validate, validated, invalid)
	rescue Errno::ENOENT
		puts "no resume file exists to resume with"
		exit
	end
else
	# note for the future: URI can't read uris unless they have a scheme, or // + path
	$target = 'http://' + $target if $target !~ /^\w+:\/\//
	$target = URI.parse($target)
	$target.path = '/' if $target.path.empty?

	$queue = LinkQueue.new
	uri = $target.clone
	uri.user = uri.password = nil
	$queue.add_uri(uri)
end

# attempt to get a list of aliases for the root host so we aren't confused when aliases are used
$aliases = [$target.host]
begin
	proper_name = Resolv.getname(Resolv.getaddress($target.host))
	parts = proper_name.split('.', 2)
	if parts.length > 1 and not $target.host.include?('.')
		$aliases << "#{$target.host}.#{parts[1]}"
		$aliases << parts[0]
	end
	$aliases << proper_name if proper_name != $target.host
rescue Resolv::ResolvError
	# doesn't matter
end
puts "alternative hostnames for #{$target.host}: #{$aliases.join(', ')}" if $options[:verbose]

uri = $target.clone
$roots = $aliases.map {|h|
	LinkToLoad.add_userpass(h, uri.user, uri.password) if uri.userinfo
	uri.host = h
	uri.dirname
}

begin
	Dir.mkdir($target.host) if $options[:duplicate]
rescue Errno::EEXIST
end

begin
	hit_nomemory = 0
	begin
		$queue.validate
	rescue NoMemoryError
		puts "out of memory\n"
	end

	puts if $options[:verbose]
	if $queue.invalid.size > 0
		puts 'broken links'
		puts "------------\n"
		$queue.invalid.each_value {|uri| puts uri.error_message if uri.reason != InvalidURI::Other_uri }
		File.delete(Resume_file) if $options[:resume]
	else
		puts 'no broken links'
	end

	if $options[:orphans]
		root = $roots[0][0..-2]
		local_uris = $queue.validated.keys.map {|uri|
			uri.query = nil
			uri.fragment = nil
			uri.to_s.sub(root, '')
		}.select {|uri| uri[0] == '/' }

		page_list = []
		Find.find($options[:orphans]) {|path|
			path = path.sub($options[:orphans], '')
			path = '/' + path if path[0] != '/'
			page_list << path
		}

		# remove files that aren't ever served by the web server and thus aren't candidates for orphanage
		[/^\/App_/, /^\/Bin/, /.ascx$/, /.vb$/, /.xml$/, /^\/css\//, /^\/javascript\//].each {|re| page_list.delete_if {|page| page =~ re } }
		page_list.delete('/site.master')
		page_list.delete('/web.config')
		page_list.delete('/web.sitemap')
		page_list.delete('/redirect.ashx')
		page_list.delete('/404.aspx')
		page_list.delete('/error.aspx')
		page_list.delete('/ratethispage_submitted.aspx')
		page_list.delete('/search.html')

		# hmm. is referenced by ie css files. should be a better way to do this...
		page_list.delete('/assets/bullet_ie6.gif')

		puts "\norphaned files"
		puts '--------------'
		js_orphans = []
		(page_list - local_uris).each {|orphan|
			if $javascript.index(orphan[1..-1])
				js_orphans << orphan
			else
				puts orphan
			end
		}

		if js_orphans.length > 0
			puts "\n" + js_orphans.join(" *\n") + " *\n"
			puts "* indicates files that were found in javascript and so might not be orphaned"
		end
	end
rescue Exception
	# save a resume file
	CSV.open(Resume_file, 'w') {|csv|
		csv << [$target]
		$queue.to_validate.values.each {|uri| csv << uri.to_a }
		$queue.validated.keys.each {|uri| csv << [uri] }
		$queue.invalid.values.each {|uri| csv << uri.to_a }
	}
	puts "a resume file has been created"
	raise $! if $!.class != Interrupt
end
