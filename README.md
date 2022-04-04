wcrawl
======

web crawler for determining broken links and simple static backup

## requirements

```
bundle install
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

- normalise the uris put into the queue so we don't get duplicates with different names
- profile the whole app to identify performance problems
