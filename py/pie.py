#!./venv/bin/python3

import argparse
import plotly

def create_pie(data):
    names = []
    amount = []
    for n, a in data.items():
        names.append(n)
        amount.append(a)

    return dict(
        type = "pie",
        labels = names,
        values = amount
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

def process_file(filename):
    algorithms = {}
    with open(filename) as f:
        for line in f.readlines()[3:]:
            parts = line.split()
            if len(parts) is 3:
                alg = parts[2]
                if alg not in algorithms:
                    algorithms[alg] = 1
                else:
                    algorithms[alg] += 1
    return algorithms

def main():
    parser = argparse.ArgumentParser(description="Create graphs from DNSSEC response sizes")
    parser.add_argument("--filename", metavar="F", type=str, nargs=1,
                        required=True, help="File to read values from")
    parser.add_argument("--title", metavar="T", type=str, nargs=1, default="",
                        help="Graph Title")
    args = parser.parse_args()

    if args.title:
        title = args.title[0]
    else:
        title = args.title

    algorithms = process_file(args.filename[0])
    trace = create_pie(algorithms)
    graph([trace], title)

if __name__ == "__main__":
    main()
