# sharkwire-api


## What is it?
This is a NodeJS application that attempt to parse Wireshark files. It has an endpoint consumed by its sister project for reading a .pcap file, parsing the frames, and doing a basic frame analysis. It returns the parsed out frames to the client for additional processing. This is the final project for Mark Mengelt in CYBER210.

## How do I use it?
I'm not sure why you'd want to in its current state but the application can be run by cloning the repo, going into the project direct and running...

    npm install

Once it's installed you can run the server by typing

    npm start

This will start up the API on port 5000. 

This will enable you to run the client program which will reach out to port 5000 on localhost. The API endpoint is not locked down by any security but does need to be run from the same server as the client to not get cors errors.