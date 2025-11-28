import time
import argparse

def simulate_log(src_path, dest_path, delay_ms):
    delay = delay_ms / 1000.0  # convert to seconds

    with open(src_path, "r") as src, open(dest_path, "w") as dest:
        for line in src:
            # write exactly as-is to the destination
            dest.write(line)
            dest.flush()      # force the line to appear immediately

            time.sleep(delay)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate a live log file being written gradually.")
    parser.add_argument("src", help="Path to source log (base data file)")
    parser.add_argument("dest", help="Path to destination log (simulated live file)")
    parser.add_argument("-d", "--delay", type=int, default=50,
                        help="Delay between writes in milliseconds (default: 50 ms)")

    args = parser.parse_args()
    simulate_log(args.src, args.dest, args.delay)
