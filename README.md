# Application level protocols and mptcp

## Scope 

Collect data about the behaviour of mptcp in presence of middle boxes.
We will start by looking at what happens at the application level (HHTP, FTP), 
and assess the behaviour of the mptcp stack in all these case with and without mptcp checksum enabled.

We want to

- be sure that mptcp works where tcp is now working, possibly after a fallback to TCP
- verify that the fallback happens correctly, and that no corner case is left unhandled
- check the behaviour of middleboxes that do not terminate the TCP connections
- run each test with and without mptcp checksum enabled

## Installation and running

The code depends on libconfig (http://www.hyperrealm.com/libconfig/), libsodium (http://doc.libsodium.org/),
libuuid.

To install packages on Debian/Ubuntu: 
apt-get install libconfig-dev uuid-dev

Install libsodium from source. We recommend you use GNU stow to manage locally installed libraries
apt-get install stow

Download libsodium from https://download.libsodium.org/libsodium/releases/, decompress it and go in the source
directory, then:

./configure --prefix=/usr/local/stow/libsodium-1.0.2
make
make install
cd /usr/local/stow
sudo stow libsodium-1.0.2

Compile client and server:
make client
make server

Run server with ./server. The client command requires one argument, the tests definition file. Examples
are in tests/. To run the suite of tests currently defined, execute:
./client tests/suite.cfg

Each run gets a id assigned, which is a truncated uuid of length defined by RUN_ID_SIZE in utils/mbd_utils.h.
Currently both client and servers log all transfer, in and out, to /tmp and /tmp/server repesctively.

Client log files have prefix indicating which type of data it contains:
- -curl : all curl logs, queries and response
- -H : received headers
- -D : received body

Similarly for the server:
- -R-H : response headers
- -R-D : response body
- -H   : query headers
- -D   : query body

Currently, tests are http requests. The client sends additional information to the server, and the server does the
same in the reverse direction.
A specific header contains the hash of the body, and another header contains the hash of all other headers. That
way both ends can check if the request was modified in transit. The server also indicates to the client if it received
headers unmodified in header X-H-HDRRCVOK.

The client can perform some validation on the response, like http status, response size, etc. New validation should be easy to add.

The server uses mongoose (http://cesanta.com/docs/Embed.shtml), which was modified to send headers described above and log all transfers.


## Tests 

Here are tests that we would run. See below for details.

- non responsive http: send an http request to a server that doesn't listen on port 80
- 404 page with ads
- customised headers: detect case changes in headers
- send http request with other protocol specified (eg ICSI)
- host headers vs IP: open an http connection to an host and set the hostname in the http pointing to another machine (eg google.com)
- cached images
- transcoding of images
- mime types
- EICAR standard visrus detection file
- IP of client: compare ip seen by server with ip of client
- FTP connection
- FTP connection with round robin scheduler and commands on each path.
- HTTP redirect

## What to validate in tests

- content-length
- http headers received by server
- http headers received by client
- port numbers in subsequent queries (identical for keep-alive, different for closing)
- http response
- hash of content

## Test-run description

Client contacts server. Here's what happens

- registers the run
- downloads the tests definition file
- server sets up stuff to collect the run's data

The client gets a run-id back.

Then the client starts to send the requests to the server. Here's how it works:

- client send request. Needs to contain run-id, test-id and query-number. 
- server gets requests, records in the run's data the test-id, query-number, and the query received. QUESTION: does the server already validate the headers received? It then handles the request and sends the response. QUESTION: does the response include what the server got in as request so the client can do a comparison?
- client gets response, validates results. If this was the last query of the test, send result to the server. If not, repeat this cycle with the next query of the test.

## Tests description

### Non-responsive HTTP

- Goal: detect a middle box terminating TCP connection.
- Desc: send an http request to a server not listening on port 80
- Expected: 
  - with problematic middle box: as it is most certainly not mptcp aware, a fall-back tcp connection should be opened, and then closed.
  - without: get a RST as port unreachable
- Additional checks: ?


### 404 page

- Goal: detect middleboxes rewriting 404 pages, possible for advertisement revenue generation
- Desc: send an HTTP request to our server generating a 404.
- Expected:
  - with problematic middle box: get a modified 404 page, and fallback to tcp when mptcp checksum active.
  - without: get the expected 404 page
- Additional checks: 
  - we might try to include some more info in the 404 page. QUESTION: which data?

### Customised headers

- Goal: detect middleboxes messing with the http headers
- Desc: send an http GET/POST/HEAD request with well specified headers, that the server can validate. We might include a hash of the headers in the URL eg. 
- Expected:
  - with problematic middle box: the headers received by the server are not what was expected, and fallback to tcp when mptcp checksum active.
  - without: get the same headers

QUESTIONS: do we look only at request headers or do we also check response headers. Might be good to do both.

### HTTP request specifying other protocol

- Goal: detect middleboxes messing with the protocol specified in the http request
- Desc: send an HTTP GET request not specifying HTTP/1.1 as protocol but some fantasy protocol
- Expected: 
  - with problematic middlebox: the request gets a correct http response from the server
  - without: the request gets an error. NOT SURE, a local test with apache accepts any protocol!

### wrong host header

- Goal: detect middleboxes that will look at the http host requested to open a tcp connection
- Desc: send an http request to our server with the host header google.com
- Expected:
  - with problematic middlebox: the response gives the google homepage
  - without: the response gives the default vhost of our server or the one configured to server requests for google.com

### cached images

- Goal: detect caching middleboxes
- Desc: send an http request for an image, then send the exact same request. Our server should serve different images for the first and second request. 
- Expected:
  - with problematic middlebox: same image received for both requests
  - without: different images for both requests
- Details: when the path /random.jpg is requested, the server sends a random image out of a set of 10 images, all images having different sizes. So the client could check if different sizes of images are received. QUESTION: is there an implication on this test if a transcoding proxy is modifying the images?

### transcoding of images

- Goal: detect caching and optimising images
- Desc: send a request for an image of known size, and compare the size received.
- Expected:
  - with problematic middlebox: image is smaller
  - without: expected size
- Details: QUESTION: Could the server send to the client a list of image urls with their respective sizes, and the client then uses this info to perform the test? Thjis could be done for all tests, eg listing which headers are set in the response.


### mime types

- Goal: ?
- Desc:
- Expected:
  - with problematic middlebox:
  - without:

### EICAR virus file

- Goal: check presence of middlebox analysing content
- Desc:
- Expected:
  - with problematic middlebox:
  - without:

QUESTION: in a paper they dropped this test due to restrictions being applied to IP having run that test

### Client IP validation

- Goal: detect NAT
- Desc: open a socket or send a GET http request, and check the IP seen by the server.
- Expected:
  - with natting middlebox: different ip
  - without: same ip.
NOTE: a private ip is always natted, so no need to run this test in that case.
QUESTION: does the client include its interfaces'IPs in the request sent?

### FTP connection

- Goal: ?
- Desc:
- Expected:
  - with problematic middlebox:
  - without:

### FTP with round robin scheduler

- Goal: 
- Desc: Send the different ftp commands on different subflows
- Expected:
  - with problematic middlebox:
  - without:

### HTTP keep-alive

- Goal: check that the "Connection: Close" header goes through unchanged
- Desc: First send 2 queries with keep-alive, and check that same ports are used for both queries, then repleat with "Connect: Close" header and check ports differ between two queries.
- Expected:
  - with problematic middlebox: Same ports used for two last queries
  - without: different ports used as tcp connection should be closed

### HTTP Redirect

- Goal: does the client get the redirect response?
- Desc: send a GET request to a URL returning a 302 or 301, and check this is what the client gets
- Expected:
  - with problematic middlebox: maybe a HTTP 200 rather than 3XX ?
  - without: the HTTP 3XX code expected
- Notes: see http://stackoverflow.com/questions/290996/http-status-code-with-libcurl for libcurl implementation.

### SMTP sending

Note: smtp is interesting but might be difficult to test as ISPq often only allow connections to their smtp servers to limit spam. Still, there the code using curl to send mails if it can help.


## Further ideas

make the same tests 
- with other http method (POST, HEAD, ...)
- with https, http/2
- with other Accept http header values 

- add distinct tests for ipv6 clients?
- define tests characteristics in a file on the server that is downloaded by the client before each run? This file needs to be versioned, and the client has to include in its report which version was run.

- trying to configure curl tests in a config file. apt-get install libconfig9 libconfig-dev
