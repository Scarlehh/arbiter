#!./venv/bin/python3

import argparse
import plotly

def create_bar(data, alg_name):
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

def create_hist(data, alg_name):
    return dict(
        type = "histogram",
        name = alg_name,
        x = data,
        histnorm = "percent"
    )

def create_cumm(data, alg_name):
    return dict(
        type = "histogram",
        name = alg_name,
        x = data,
        histnorm = "percent",
        cumulative=dict(enabled=True),
        opacity=0.75
    )

def graph(traces, title, r=None):
    layout = dict(
        title = title,
        xaxis = dict(
            title = "size (bytes)",
            dtick = 64
        ),
        yaxis = dict(
            title = "frequency"
        ),
        barmode = "overlay"
    )

    if r:
        layout["xaxis"]["range"] = r

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
    parser.add_argument("--chart", metavar="C", type=str, nargs=1,
                        choices=["bar", "hist", "cumm"], required=True,
                        help="Specify chart to display")
    parser.add_argument("--rang", metavar="r", type=int, nargs=2,
                        help="Set graph range")
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
    chart = args.chart[0]
    for i in range(len(rrsize)):
        if chart == "bar":
            traces.append(create_bar(rrsize[i], algs[i]))
        elif chart == "hist":
            traces.append(create_hist(rrsize[i], algs[i]))
        elif chart == "cumm":
            traces.append(create_cumm(rrsize[i], algs[i]))

    rang = None
    if args.rang:
        rang = [args.rang[0], args.rang[1]]
    graph(traces, title, rang)

if __name__ == "__main__":
    main()
