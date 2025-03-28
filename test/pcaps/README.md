# PCAPs

- nfdc-route-add.pcap

This was collected by using client.conf to set the default way to communicate with NFD to TCP:

    $ grep transport ~/.ndn/client.conf 
    ; "transport" specifies Face's default transport connection.
    ;transport=unix:///var/run/nfd.sock
    transport=tcp://127.0.0.1

Then tcpdump was run on localhost:

    tcpdump -i lo -w nfdc-route-add.pcap

Finally, the route command was sent (which will go over localhost now as defined in client.conf)

    nfdc route add prefix /test/ndn nexthop 259 cost 100

- ndnlpv2.pcap

    Copied from [ndn-tools](https://github.com/named-data/ndn-tools)
