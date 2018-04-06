#!./venv/bin/python3

import argparse
import plotly

def create_data(data, alg_name):
    return dict(
        type = "bar",
        name = alg_name,
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

def graph(traces, title):
    layout = dict(
        title = title
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
                        required=True, help="File to read values from")
    parser.add_argument("--title", metavar="T", type=str, nargs=1, default="",
                        help="Graph Title")
    parser.add_argument("--algorithms", metavar="A", type=int, nargs="+",
                        choices=[3, 5, 6, 7, 8, 10, 13, 14, 15],
                        required=True, help="Algorithms to appear in graph")
    args = parser.parse_args()

    if args.title:
        title = args.title[0]
    else:
        title = args.title

    algs = args.algorithms
    rrsize = []
    for a in algs:
        rrsize.append(process_file(args.filename[0], a))

    traces = []
    for i in range(len(rrsize)):
        traces.append(create_data(rrsize[i], algs[i]))

    graph(traces, title)

if __name__ == "__main__":
    main()
