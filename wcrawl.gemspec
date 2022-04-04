Gem::Specification.new do |s|
  s.name = 'wcrawl'
  s.summary = 'web crawler for determining broken links and simple static backup'
  s.version = '1.0.0'
  s.licenses = ['MIT']
  s.authors = ['Daniel Cavanagh']
  s.homepage = 'https://rubygems.org/gems/wcrawl'
  s.metadata = { "source_code_uri" => "https://github.com/danielcavanagh/wcrawl" }
  s.files = Dir['lib/**/*.rb'] + Dir['bin/*']
  s.executables = ['wcrawl']
end
