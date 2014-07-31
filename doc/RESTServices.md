# Setting up arbitrary REST services

## Requests

To request a REST service endpoint the following request format can be used:

    <METHOD> /open/<account>/<container>/<zerovm app path>?<query string>

Where:
 
- `<METHOD>` can be: `GET`, `HEAD`, `POST`, `PUT`, `DELETE`
- `<account>` is the account name from `X-Auth-Storage-Url`
- `<container>` is the container name
- `<zerovm app path>` is the object name of the ZeroVM app archive (.zapp) 
that implements the REST service
- `<query string>` is the request query string

If you have a trouble using `/open/...` endpoint you can use standard 
`X-Auth-Storage-Url` but will have to set additional header: 
`X-Zerovm-Execute: open/1.0`

## How does it work?

Your application will be invoked by fetching the `boot/system.map` from the 
application archive and executing a job stored there.

Your application will get the `QUERY_STRING` and all other CGI-like 
environment variables set in the environment. Including `REQUEST_METHOD`, 
`REQUEST_URI` and many more useful data items about the request.

### Reading a request payload

If your application defines the following channel `{ "name": "stdin" }` (an 
`stdin` channel without path or any other parameters set) the payload of the
 request (`POST` or `PUT` requests usually have a payload) can be consumed 
 by reading the `stdin`.
 
## Responses

It's up to application to produce any relevant response.

## Examples

### Handling GET

system.map:

    [{
        "name": "db-select",
        "exec": {"path": "swift://./db-select/api.zapp"},
        "devices": [
            {"name": "input",
                "path": "swift://./db-select/my.db"},
            {"name": "stdout",
                "content_type": "message/cgi"}
        ]
    }]
    
request:

    GET /open/AUTH_test_account/db-select/api.zapp?select=select+*+from+my_table+where+name+%3D+%22Joe%22
    
application logic:
    
1. See if `$REQUEST_METHOD == "GET"`
2. Parse `$QUERY_STRING`, you will get `select * from my_table where name = 
"Joe"` after url decode.
3. Run the select on top of my.db object, connected to `/dev/input` channel.
4. Send the response, for example encoded as JSON.

response:

    Status: 200 OK
    Content-Type: application/json
    
    [
        { "name": "Joe", "title": "Mr.", "id": 101 }
    ]
    
### Handling POST

system.map:

    [
        {
            "name": "sort",
            "exec": {"path": "swift://./sort-app/sort.zapp"},
            "devices": [
                {"name": "stdin"},
                {"name": "stdout",
                 "content_type": "application/json"
                }
            ]
        }
    ]
    
request:

    POST /open/AUTH_test_account/sort-app/sort.zapp
    Content-Type: application/json
    
application logic:
    
1. Check if `$REQUEST_METHOD == "POST"`
2. Check that `Content-Type` is correct.
3. Consume the payload by reading `/dev/stdin`
4. Parse payload as JSON
5. Sort the payload
6. Return the sorted payload as JSON response

response:
   
    [1, 2, 3, 4, 5]