# -*- mode: python -*-

import argparse
import asyncio

from scapyndn.pkt import *
from scapyndn.contents.nfd import *
from scapyndn.key_chain import get_signed_interest_with_default_key

from ndn.transport.stream_face import TcpFace

async def on_pkt(typ, data):
    NdnGuessPacket(data).show2()

async def main(args):
    f = TcpFace()
    f.callback = on_pkt
    await f.open()
    interest = None
    if args.command == "status":
        if args.report:
            for status_name in [
                    NameComponent(value="status") / NameComponent(value="general"),
                    NameComponent(value="faces") / NameComponent(value="channels"),
                    NameComponent(value="faces") / NameComponent(value="list"),
                    NameComponent(value="fib") / NameComponent(value="list"),
                    NameComponent(value="rib") / NameComponent(value="list"),
                    NameComponent(value="cs") / NameComponent(value="info"),
                    NameComponent(value="strategy-choice") / NameComponent(value="list")
            ]:
                n = Name(value = NameComponent(value="localhost") /
                                 NameComponent(value="nfd") /
                                 status_name)
                interest = Interest(value = n / CanBePrefix() / MustBeFresh())
                f.send(raw(interest))

        if args.show:
            n = Name(value = NameComponent(value="localhost") /
                     NameComponent(value="nfd") /
                     NameComponent(value="status") /
                     NameComponent(value="general"))
            interest = Interest(value = n / CanBePrefix() / MustBeFresh())
            f.send(raw(interest))
    elif args.command == "route":
        if args.list is True:
            n = Name(value = NameComponent(value="localhost") /
                     NameComponent(value="nfd") /
                     NameComponent(value="rib") /
                     NameComponent(value="list"))
            interest = Interest(value = n / CanBePrefix() / MustBeFresh())
            f.send(raw(interest))
        if args.add is True:
            name_to_reg = Name.get_name(args.prefix)
            ctrl_param_val = name_to_reg
            if args.face_id is not None:
                # Throw if face-id is none
                ctrl_param_val /= FaceId(value=args.face_id)
            if args.origin is not None:
                ctrl_param_val /= Origin(value=args.origin)
            if args.cost is not None:
                ctrl_param_val /= Cost(value=args.cost)
            # flags
            cp = ControlParameters(value=ctrl_param_val)
            interest_name_val = Name.concat_comp_from_str("/localhost/nfd/rib/register") / \
                NameComponent(value=cp)

            i = get_signed_interest_with_default_key(interest_name_val)
            # i.show2()
            f.send(raw(i))

    try:
        await f.run()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':

    parser = argparse.ArgumentParser(prog='PROG')
    subparsers = parser.add_subparsers(dest='command', help='subcommand help')

    parser_a = subparsers.add_parser('status', help='status subcommand')
    group = parser_a.add_mutually_exclusive_group()
    group.add_argument('--report', action='store_true', help='print full status report')
    group.add_argument('--show', action='store_true', help='print general status')

    parser_b = subparsers.add_parser('strategy', help='strategy subcommand')
    group = parser_b.add_mutually_exclusive_group()
    group.add_argument('--show', action='store_true', help='print general status')

    parser_c = subparsers.add_parser('route', help='route subcommand')
    group = parser_c.add_argument_group()
    group.add_argument('--list', action='store_true', help='')
    group.add_argument('--add', action='store_true', help='add route')
    group.add_argument('--remove', action='store', help='')
    group.add_argument('--prefix', action='store', help='')
    group.add_argument('--nexthop', action='store', help='')
    group.add_argument('--cost', action='store', type=int, default=0, help='')
    group.add_argument('--origin', action='store', type=int, default=255, help='')
    group.add_argument('--face-uri', action='store', help='')
    group.add_argument('--face-id', action='store', type=int, help='')
    group.add_argument('--expires', action='store', help='')

    args = parser.parse_args()
    # print(args)

    asyncio.run(main(args))
