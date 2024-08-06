#!/usr/bin/env python3
import atexit
import os
import subprocess
import sys
import time


class Server:
    def __init__(self, addr):
        os.environ["ATOMIC_SERVER_URL"] = f"http://{addr}:9883"
        self.addr = addr
        self.atomic = None
        self.node = None

    def pull(self):
        subprocess.run(["git", "pull"])

    def init(self):
        print("Initializing...")
        subprocess.run(
            [
                "sed",
                "-i",
                f"s/localhost/{self.addr}/g",
                "./browser/vihreat-lib/atomic.config.json",
            ],
            check=True,
        )
        subprocess.run(["./init.sh", "--force"], check=True)

    def start(self):
        print("Starting atomic...")
        self.atomic = subprocess.Popen("./server.sh")
        print("Starting node...")
        self.atomic = subprocess.Popen(["./start.sh", "--host"])

    def stop(self):
        if self.atomic:
            print("Terminating atomic...")
            self.atomic.terminate()
            self.atomic.wait()
            self.atomic = None
        if self.node:
            print("Terminating node...")
            self.node.terminate()
            self.node.wait()
            self.node = None

    def restart(self):
        self.stop()
        self.pull()
        self.init()
        self.start()

    def run(self):
        self.pull()
        self.init()
        self.start()
        atexit.register(self.stop)
        while True:
            time.sleep(1)


if __name__ == "__main__":
    addr = sys.argv[1]
    server = Server(addr)
    server.run()
