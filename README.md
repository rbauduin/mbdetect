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
- Desc: send an http request for an image, then send the exact same request. Our server should server different images for the first and second request. 
- Expected:
  - with problematic middlebox: same image received for both requests
  - without: different images for both requests

### transcoding of images

- Goal: detect caching and optimising images
- Desc: send a request for a big image, then resend the same request
- Expected:
  - with problematic middlebox: second image is smaller
  - without: same images for both requests

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




