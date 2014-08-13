# Zerocloud CGI environment variables

Zerocloud exposes standard CGI environment variables to the user applications
It also uses some non-standard variables, related to files attached locally 
to the session

## Standard vars

### Permanent vars

    "GATEWAY_INTERFACE": "CGI/1.1"
    "SERVER_NAME": "<hostname>"
    "SERVER_PORT": "<port>", 
    "SERVER_PROTOCOL": "HTTP/<version>"
    "SERVER_SOFTWARE": "zerocloud"

Here `<hostname>`, `<port>` and `<version>` depend on the server software 
and configuration.

### Request-based vars

      "PATH_INFO": "<request path_info>"
      "REMOTE_USER": "<authenticated user data>"
      "REQUEST_METHOD": "<method>" 
      "REQUEST_URI": "<original URI>"
      "SCRIPT_FILENAME": "<executable path>"
      "SCRIPT_NAME": "<node name>"
      "QUERY_STRING": "<query string>"
      
Here

- `<request path_info>` - request path info, without `version` string and 
`query string`
- `<authenticated user data>` - authorization data, user name, groups, etc.,
 in Swift acl/auth format
- `<method>` - original request method, ex. `POST`
- `<original URI>` - original request URI, includes full URI:  
`/<version>/<request path_info>?<query string>`
- `<executable path>` - path to executable from `exec` property, 
see `doc/Servlets.md`
- `<node name>` - node name from `name` property, 
see `doc/Servlets.md`
- `<query string>` - request query string, if exists

## Non-standard local file vars

      "LOCAL_CONTENT_LENGTH": "<file size>"
      "LOCAL_CONTENT_TYPE": "<file content_type>"
      "LOCAL_DOCUMENT_ROOT": "<device name>"
      "LOCAL_HTTP_ETAG": "<file md5 etag>"
      "LOCAL_HTTP_X_TIMESTAMP": "<file timestamp>"
      "LOCAL_OBJECT": "on"
      "LOCAL_PATH_INFO": "<object path info>"

Here

- `LOCAL_OBJECT` - is used to check if the session has a local file 
attached, if `LOCAL_OBJECT` variable is set, application can check other 
`LOCAL_*` vars
- `<object path info>` - Swift path_info for the object: 
`/<account>/<container>/<object>`
- `<file size>` - Swift object `content-length`
- `<file content_type>` - Swift object `content-type`
- `<file md5 etag>` - Swift object `etag` property
- `<file timestamp>` - Swift object creation timestamp
- `<device name>` - device name from `device.name` property, 
in the form of `/dev/<name>`, see `doc/Servlets.md`

Other metadata properties can be attached to the object and will be 
exposed through `LOCAL_HTTP_X_OBJECT_META_*` variables

## Header-based vars

There could be quite a lot of request headers exposed to the application, 
a short list (from typical Firefox request is below)

      "HTTP_ACCEPT": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      "HTTP_ACCEPT_ENCODING": "gzip, deflate"
      "HTTP_ACCEPT_LANGUAGE": "en-US,en;q=0.5"
      "HTTP_CACHE_CONTROL": "no-cache"
      "HTTP_CONNECTION": "close"
      "HTTP_HOST": "<hostname>"
      "HTTP_PRAGMA": "no-cache"
      "HTTP_REFERER": "https://my.host.com/index.html?account=user_id:user_name"
      "HTTP_USER_AGENT": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0"

There are also Swift specific and Zerocloud specific headers exposed to 
application

      "HTTP_X_ZEROVM_EXECUTE": "<execute version>"
      "HTTP_X_ZEROVM_TIMEOUT": "<timeout>"

Here

- `<execute version>` - execution type, see `doc/Requests.md` and 
`doc/RESTServices.md`
- `<timeout>` - session timeout, in seconds, session will be terminated if 
timeout reached