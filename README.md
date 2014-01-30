wcrawl
======

web crawler for determining broken links and simple static backup

## requirements

```
gem typhoeus
```

## usage

```
wcrawl.rb [-csv] [-t <num>] [-o dir] <uri>
wcrawl.rb [-cv] [-t <num>] -r

-c: check within comment tags (<!-- comment -->)
-d: download and save to the current local directory
-o: match the validated urls against a local directory to discover orphaned pages
-r: resume an interrupted scan
-s: check just the first page (ie. not recursive)
-v: be verbose (eg. warn on improperly escaped urls, etc.)
```

## todo

- profile the whole app to identify performance problems
- remove use of globals within classes
- move csv stuff into LinkQueue where it belongs
- citrix does weird things with proxies
- normalise the uris put into the queue so we don't get duplicates with different names
- don't outright reject https links. they need to work too
- unit tests
