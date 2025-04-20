# -*- mode: python -*-

import argparse
import asyncio
import sys

from scapy.compat import raw
from scapyndn.pkt import (
    NameComponent,
    Name,
    Interest,
    NdnGuessPacket,
    CanBePrefix,
    MustBeFresh,
    VersionNameComponent
)
from scapyndn.contents.nfd import (
    FaceId,
    Uri,
    Cost,
    Origin,
    Flags,
    ExpirationPeriod,
    ControlParameters,
    Strategy
)
from scapyndn.key_chain import get_signed_interest_with_default_key
from ndn.transport.stream_face import TcpFace


async def on_pkt(typ, data):
    NdnGuessPacket(data).show2()


async def main(parser, args):
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
                NameComponent(value="strategy-choice") /
                    NameComponent(value="list")
            ]:
                n = Name(value=NameComponent(value="localhost") /
                         NameComponent(value="nfd") /
                         status_name)
                interest = Interest(value=n / CanBePrefix() / MustBeFresh())
                f.send(raw(interest))

        if args.show:
            n = Name(value=NameComponent(value="localhost") /
                     NameComponent(value="nfd") /
                     NameComponent(value="status") /
                     NameComponent(value="general"))
            interest = Interest(value=n / CanBePrefix() / MustBeFresh())
            f.send(raw(interest))
    elif args.command == "route":
        if args.list is True:
            n = Name(value=NameComponent(value="localhost") /
                     NameComponent(value="nfd") /
                     NameComponent(value="rib") /
                     NameComponent(value="list"))
            interest = Interest(value=n / CanBePrefix() / MustBeFresh())
            f.send(raw(interest))
        elif args.add is True:
            ctrl_param_val = Name.get_name(args.prefix)
            if args.nexthop is None:
                print("Please provide nexthop")
                f.shutdown()
                sys.exit(1)

            try:
                ctrl_param_val /= FaceId(value=int(args.nexthop))
            except Exception:
                ctrl_param_val /= Uri(value=args.nexthop)

            if args.origin is not None:
                ctrl_param_val /= Origin(value=args.origin)
            if args.cost is not None:
                ctrl_param_val /= Cost(value=args.cost)
            if args.flags is not None:
                ctrl_param_val /= Flags(value=args.flags)
            if args.expiration is not None:
                ctrl_param_val /= ExpirationPeriod(value=args.expiration)

            cp = ControlParameters(value=ctrl_param_val)
            interest_name_val = \
                Name.concat_comp_from_str("/localhost/nfd/rib/register")
            interest_name_val /= NameComponent(value=cp)

            interest = get_signed_interest_with_default_key(interest_name_val)
            # interest.show2()
        elif args.remove is True:
            ctrl_param_val = Name.get_name(args.prefix)
            if args.nexthop is not None:
                try:
                    ctrl_param_val /= FaceId(value=int(args.nexthop))
                except Exception:
                    ctrl_param_val /= Uri(value=args.nexthop)
            if args.origin is not None:
                ctrl_param_val /= Origin(value=args.origin)
            cp = ControlParameters(value=ctrl_param_val)
            interest_name_val = \
                Name.concat_comp_from_str("/localhost/nfd/rib/unregister")
            interest_name_val /= NameComponent(value=cp)
            interest = get_signed_interest_with_default_key(interest_name_val)
            # interest.show2()
    elif args.command == "strategy":
        if args.list is True:
            n = Name(value=NameComponent(value="localhost") /
                     NameComponent(value="nfd") /
                     NameComponent(value="strategy-choice") /
                     NameComponent(value="list"))
            interest = Interest(value=n / CanBePrefix() / MustBeFresh())
        elif args.set is True:
            if args.prefix is None or args.strategy is None:
                print("Need --prefix <> --strategy <>")
                f.shutdown()
                sys.exit(1)

            strategy = Strategy(value=Name.get_name(
                args.strategy, {"v": (VersionNameComponent, int)}))
            cp = ControlParameters(value=Name.get_name(args.prefix) / strategy)
            interest_name_val = \
                Name.concat_comp_from_str("/localhost/nfd/strategy-choice/set")
            interest_name_val /= NameComponent(value=cp)
            interest = get_signed_interest_with_default_key(interest_name_val)
            # interest.show2()
        elif args.unset is True:
            if args.prefix is None:
                print("Need --prefix <>")
                f.shutdown()
                sys.exit(1)

            cp = ControlParameters(value=Name.get_name(args.prefix))
            interest_name_val = \
                Name.concat_comp_from_str("/localhost/nfd/strategy-choice/unset")
            interest_name_val /= NameComponent(value=cp)
            interest = get_signed_interest_with_default_key(interest_name_val)
    elif args.command == "cs":
        if args.info is True:
            n = Name(value=NameComponent(value="localhost") /
                     NameComponent(value="nfd") /
                     NameComponent(value="cs") /
                     NameComponent(value="info"))
            interest = Interest(value=n / CanBePrefix() / MustBeFresh())

    if interest is not None:
        f.send(raw(interest))

        try:
            await f.run()
        except asyncio.CancelledError:
            pass
        finally:
            f.shutdown()
    else:
        parser.print_help()


def entry():
    parser = argparse.ArgumentParser(prog="sn-nfdc")
    subparsers = parser.add_subparsers(dest="command", help="subcommand help")

    parser_a = subparsers.add_parser("status", help="status subcommand")
    group = parser_a.add_mutually_exclusive_group()
    group.add_argument("--report", action="store_true",
                       help="print full status report")
    group.add_argument("--show", action="store_true",
                       help="print general status")

    parser_b = subparsers.add_parser("strategy", help="strategy subcommand")
    group = parser_b.add_argument_group()
    group.add_argument("--list", action="store_true",
                       help="print general status")
    group.add_argument("--set", action="store_true",
                       help="print general status")
    group.add_argument("--unset", action="store_true",
                       help="print general status")
    group.add_argument("--prefix", action="store", help="")
    group.add_argument("--strategy", action="store", help="")

    parser_c = subparsers.add_parser("route", help="route subcommand")
    group = parser_c.add_argument_group()
    group.add_argument("--list", action="store_true", help="")
    group.add_argument("--add", action="store_true", help="add route")
    group.add_argument("--remove", action="store_true", help="remove route")
    group.add_argument("--prefix", action="store", help="")
    group.add_argument("--nexthop", action="store", help="")
    group.add_argument("--cost", action="store", type=int, default=0, help="")
    group.add_argument("--origin", action="store", type=int, default=255,
                       help="default=255 i.e. static")
    group.add_argument("--flags", action="store", type=int, default=1,
                       help="child-inherit=1, capture=2")
    group.add_argument("--expiration", action="store", type=int, help="")

    parser_d = subparsers.add_parser("cs", help="strategy subcommand")
    group = parser_d.add_mutually_exclusive_group()
    group.add_argument("--info", action="store_true",
                       help="print general status")

    args = parser.parse_args()
    # print(args)

    try:
        asyncio.run(main(parser, args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    entry()
