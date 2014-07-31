# Using job chaining middleware

Job chain middleware allows chaining jobs by feeding output of a job back to
 Zerocloud to launch a new job
 
## Configuration

Add the following to proxy-server config

    [filter:job-chain]
    use = egg:zerocloud#job_chain
    
Place `job-chain` in the proxy-server pipeline.  
It should come before `proxy-query` middleware but after all auth-related 
middlewares.

### Configuration options

`zerovm_maxconfig = 65536` - maximum length of the JSON job description (see
 `doc/Servlets.md` and `doc/Configuration.md`) in bytes, 
 ex. max. size of `boot/system.map` file

`chain_timeout = 20` - timeout waiting for all chained jobs to finish, 
in seconds. It is used to prevent jobs entering an infinite loop by chaining
 one after another.

## Requests

To use job chain you can issue any request described in `doc/Requests.md`

## Responses

If `job-chain` is installed in the pipeline, you will get one more header in 
the HTTP response:

`X-Chain-Total-Time` - the header will have format of `000.000` in seconds. 
It will give the total time of all jobs in chain. And will be equal to total
 time of one job if the job was not chained.

## How to start a chain?

To start a chain you need a job that will send HTTP response with the 
following properties:

- Header `Content-Type: application/json` should be set.
- Header `X-Zerovm-Execute: 1.0` should be set.
- Payload of the response should be a JSON job description (see 
`doc/Servlets.md`)
- Header `Content-Length : <length>` should be set to a size of the JSON 
payload.

To send such output one of the output channels (preferably `stdout`) should 
be set to no path and CGI/HTTP content type. Example:

    {
        "name": "my-parent-job",
        ........
        "devices": [
            { "name": "stdout",
              "content_type": "message/http"
            },
            .......
        ]
    }
    
In case of `message/http` the job should write the following response to 
`stdout` (just an example):

    HTTP/1.1 200 OK
    Content-Type: application/json
    X-Zerovm-Execute: 1.0
    Content-Length: 126
    
    [{
        "name": "my-child-job",
        "devices": [
        .......
        ......
        .....
    }]
    
In case of `message/cgi`:

    Status: 200 OK
    Content-Type: application/json
    X-Zerovm-Execute: 1.0
    Content-Length: 126
    
    [{
        "name": "my-child-job",
        "devices": [
        .......
        ......
        .....
    }]
    
The job you start this way can obviously output another job description and 
set proper headers, and then another chain will start, and so on.  
The last job that will send either a response without `X-Zerovm-Execute` set
 or no response body at all will finish the chain.  
Chain will also terminate if more than `chain_timeout` time passed since the
 first job started.
 
## Consuming request payload

The first request that starts the chain can be a request with a payload 
(example: POST or PUT request, see `doc/RESTServices.md`) 
 
Which job in chain will get the payload?  

To consume a payload a job should set up a special `stdin` channel, 
see `doc/RESTServices.md`  
The first job that sets such a channel has a chance to consume the payload, 
by reading from its `stdin`.

If the job did not consume payload completely, the next job in chain has a 
chance to do so, if it also sets up `stdin` correctly, and so on.
Most useful cases for that would be using the first job to set up specific 
channels and then running second job that will consume request payload store
 it using these channels.