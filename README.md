# Scapy NDN

`scapyndn` is a python library which provides
Named-Data Networking (NDN) packet definitions for `scapy`
along with various tools and helpers. Packets can be sent/received
via various wrapper functions (over sockets) provided by scapy
or the more NDN way by using python-ndn`'s Face (asyncio).

```python
from scapy.layers.l2 import Ether
from scapyndn.pkt import *

pkt = Ether(dst="01:00:5e:00:17:aa", type=0x8624) / \
  Interest(value=
    Name(value=
       NameComponent(value="hello") /
       NameComponent(value="ndn")
    ) /
    MustBeFresh()
  )
pkt.show2()

###[ Ethernet ]###
  dst       = 01:00:5e:00:17:aa
  src       = 00:00:00:00:00:00
  type      = 0x8624
###[ Interest ]###
   type      = 5
   length    = 16
   \value     \
    |###[ Name ]###
    |  type      = 7
    |  length    = 12
    |  \value     \
    |   |###[ Name Component (String) ]###
    |   |  type      = 8
    |   |  length    = 5
    |   |  value     = b'hello'
    |   |###[ Name Component (String) ]###
    |   |  type      = 8
    |   |  length    = 3
    |   |  value     = b'ndn'
    |###[ MustBeFresh ]###
    |  type      = 18
    |  length    = 0
```

## Install

    cd scapy-ndn
    python3 -m venv ndn-scapy-venv
    source ndn-scapy-venv/bin/activate
    pip install -e .

## Run tests

Run all the tests:

    python3 -m scapy.tools.UTscapy -c test/config/ndn.utsc 

Run specific tests:

	python3 -m scapy.tools.UTscapy -t test/nfd.uts
    python3 -m scapy.tools.UTscapy -t test/binding.uts
