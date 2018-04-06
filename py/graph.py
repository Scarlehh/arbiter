import argparse
import plotly

def create_data(data):
    return dict(
        type = "bar",
        x = data,
        y = data,
        transforms = [dict(
            type = "aggregate",
            groups = data,
            aggregations = [dict(
                target = "y", func = "count", enabled = True)
            ]
        )]
    )

def graph(traces, rr):
    layout = dict(
        title = "{} +dnssec Response Sizes".format(rr)
    )

    plotly.offline.plot(
        {
            "data": traces,
            "layout": layout
        },
        validate=False
    )

def process_file(filename, alg):
    rrsize = []
    with open(filename) as f:
        for line in f.readlines()[3:]:
            parts = line.split()
            if len(parts) is 3 and int(parts[2]) == alg:
                rrsize.append(int(parts[1]))
    return rrsize

def main():
    parser = argparse.ArgumentParser(description="Create graphs from DNSSEC response sizes")
    parser.add_argument("--filename", metavar="F", type=str, nargs=1,
                        help="File to read values from")
    parser.add_argument("--record", metavar="t", type=str, nargs=1,
                        help="Resource record type being processed")
    args = parser.parse_args()

    if not args.filename:
        print("Filename required")
        exit(1)

    rrsize = process_file(args.filename[0], 13)

    trace = create_data(rrsize)
    graph([trace], "DNSKEY")

if __name__ == "__main__":
    main()
