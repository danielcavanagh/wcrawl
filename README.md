wcrawl
======

web crawler for determining broken links and simple static backup

## todo

- profile the whole app to identify performance problems
- remove use of globals within classes
- move csv stuff into LinkQueue where it belongs
- citrix does weird things with proxies
- normalise the uris put into the queue so we don't get duplicates with different names
- don't outright reject https links. they need to work too
