# Zerocloud request types

## POST

To issue POST request in Zerocloud you need to add `X-Zerovm-Execute: 1.0` header to the request.

You can issue several types of POST requests it all depends on what `Content-Type` you pass there.

- `Content-Type: application/json` - POST a job description

- `Content-Type: application/x-tar` or `Content-Type: application/x-gtar` or `Content-Type: application/x-ustar` - POST ZeroVM image

- any other `Content-Type` - POST a script to be handled by some interpreter or shell executable.

## GET

To issue a GET request in Zerocloud you need to specify particular version string in Swift storage url.

Just a reminder, Swift url contains the following components:

- protocol
- hostname
- port
- `version`
- account
- container
- object

<pre>
protocol://hostname:port/version/account/container/object
</pre>

The supported version strings are:

- open - will execute binary associated with `Content-Type` of the object you're GET-ting, akin to any file manager `double-click` function.

- open-with - not implemented yet


### POST a job description

This POST will work only if url path info is of the form: /version/account

If you issue a POST with `Content-Type: application/json` and `X-Zerovm-Execute: 1.0` it will be interpreted as a job description.
The data in the POST request will be parsed as a JSON document and then interpreted according to `doc/Servlets.md`.
All objects that are mentioned in JSON file must already exist as Swift objects (if they are readable)
or be created by the job you're trying to run (if writable).
This is the best use-case for preconfigured jobs where there are little changes between the runs.
It's best suited for clustered runs, where you get a lot of nodes working on different objects and communicating with each other.


### POST a ZeroVM image file

This POST will work only if url path info is of the form: /version/account

If you issue a POST with `Content-Type: any of the tar file types` and `X-Zerovm-Execute: 1.0` it will be interpreted as a ZeroVM image.
ZeroVM image is a tar file with several files and directories inside.
The minimal ZeroVM image contains just a `boot/system.map` file.
This file is a JSON job description file exactly the same as in a 'POST job description' topic above.
Image can contain any number of files, all these files will be visible to the running ZeroVM instance as its local `root` filesystem.
Essentially it's like "mounting" this tar file to `/`
This tar file can also contain the executable itself. If `boot/system.map` has a realtive path in `exec['path']` variable,
the executable will be extracted from the image file and only then ZeroVM session will run.
You can always incapsulate all the data your executable needs in this file: config files, executable, data files, libraries, etc.
`boot/system.map` can referense not only files inside the image but also files outside by using absolute paths.
You can also have `boot/cluster.map` in the image. This JSON file will execute clustered jobs.
The image file will be made available as a local filesystem on all the nodes in the cluseter.
You can even reference different executables from the same image file to run on different nodes.

### POST any other file

This POST will work if url path info is of the form: /version/account or /version/account/container/object

If you issue a POST with `X-Zerovm-Execute: 1.0` and any other content type the data will be interpreted as a script.
Each script must contain a "shebang" line at the top (reminder: #! ).
Shebang can either include a full path to the executable, or include a system image file name (see. Configuration.md)
and a relative path to the executble inside the system image file.

- If you POST to /version/account the script will run on any available node and the result (stdout) will be sent back to you as 'text/plain'
- If you POST to /version/account/container/object the script will be run with the object file as input (stdin) and the result (stdout) will be sent back to you as 'text/plain'

Shebang examples:

    #! /my_container/bin/python
    #! system_python bin/python
    #! system_linux bin/sh

    system_python and system_linux are names of the system images

When your script is run, the filesystem will have it mounted as a `/script` file (absolute path, directly in root dir).
The interpreter will have its home dir set to `/` and executed as `/path/to/interpreter script`
If you want to get stderr or mount any other files into executable filesystem, you have to use other POST formats (preferrably: POST a ZeroVM image)

### GET with version `open`

This GET will work if url path info is of the form: /version/account/container/object

When you issue a GET request with version `open`: `/open/account/container/object` the following events will fire:

- Zerocloud will get `Content-Type` of the object in url
- Zerocloud will search for object with path /version/account/.zvm/content-type/config in Swift
- if the object is found its contents will be used as a JSON job description template
- the template will be filled with details from GET resuest: object url and parts of query string
- the final JSON file will run and the result will be returned to user as a GET response

Example:

    GET /open/my_account/documents/my_doc.pdf -> Content-Type: application/x-pdf
    GET /v1/.zvm/application/x-pdf/config -> template


GET templates format is simple, it's a regular JSON file but with some sort of substitution variables.
Each variable has format of `"{.variable_name=default value}"`.
If GET request has a query string all query params will be expanded as a key->val dictionary and substituted instead of the matching template variables.
If there is no such variable in query string the default value will be substituted.
Example:

    template: {"args": "{.format=xml}"}
    if query string is: ?attr=val&format=pdf
    resulting JSON: {"args": "pdf"}
    if query string is: ?attr=val
    resulting JSON: {"args": "xml"}

The object path info `/container/object` will be substituted instead of the reserved `{.object_path}` variable.

Issuing GET request for objects with `Content-Type: application/x-nexe` will try to run these objects as ZeroVM executables.
STDOUT contents will be sent to the user in GET response. If you supply the following query string params: "args", "content_type"
they will be substituted for executable argument string and response Content-Type respectively.