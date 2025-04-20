# Tools

## nfdc

Show status:

    sn-nfdc status --show
	
Report status:

    sn-nfdc status --report

Add and remove routes:

    sn-nfdc route --add --prefix /test/ndn3 --nexthop 268 --cost 100 
    sn-nfdc route --remove --prefix /test/ndn2 --nexthop 268

Strategy management:

    sn-nfdc strategy --list
