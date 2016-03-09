#!/usr/bin/env python

import threading
import Queue
import time
import signal
import itertools
# requires dnspython
import dns.exception
import dns.query
import dns.rdatatype

class Result(object):
    def __init__(self, query, ans, elapsed):
        self.query = query
        self.ans = ans
        self.elapsed = elapsed


class QueryThread(threading.Thread):
    def __init__(self, q, r, *args, **kwargs):
        super(QueryThread, self).__init__(*args, **kwargs)
        self.q = q
        self.r = r

    def run(self):
        while True:
            try:
                domain = self.q.get(True, 1)
            except Queue.Empty:
                break
            query = dns.message.make_query(domain, dns.rdatatype.A)
            try:
                stime = time.time()
                ans = dns.query.udp(query, '127.0.0.1', timeout=2, port=7001)
                elapsed = time.time() - stime
            except dns.exception.Timeout:
                ans = None
                elapsed = 2
            finally:
                res = Result(query, ans, elapsed)
                self.r.put(res)

class ReportThread(threading.Thread):
    def __init__(self, r, *args, **kwargs):
        super(ReportThread, self).__init__(*args, **kwargs)
        self.r = r
        self.total = 0
        self.finished = 0
        self.total_wait = 0
        self.finished_wait = 0

    def report(self):
        timeout = self.total - self.finished
        avg_wait = self.total_wait / self.total
        avg_finished_wait = self.finished_wait / self.finished
        report = (
       '            total: %(total)d\n'
       '         finished: %(finished)d\n'
       '          timeout: %(timeout)d\n'
       '         avg_wait: %(avg_wait).3f\n'
       'avg_finished_wait: %(avg_finished_wait).3f\n'
        )
        report = report % {
            'total': self.total,
            'finished': self.finished,
            'timeout': timeout,
            'avg_wait': avg_wait,
            'avg_finished_wait': avg_finished_wait,
        }
        print report

    def run(self):
        global stop
        while True:
            try:
                r = self.r.get(True, 1)
            except Queue.Empty:
                if stop:
                    self.report()
                    break
                else:
                    continue
            self.total += 1
            self.total_wait += r.elapsed
            if r.ans is not None:
                self.finished += 1
                self.finished_wait += r.elapsed

class UtdnsdThread(threading.Thread):
    pass

domains = (
    'www.baidu.com',
    'www.twitter.com',
    'www.facebook.com',
    'www.vimeo.com',
    'mail.google.com',
    'www.google.com',
    'www.amazon.com',
    'aws.amazon.com',
    'www.openvpn.net',
    'unix.stackexchange.com',
)

stop = False
def sighand(signum, frame):
    global stop
    stop = True

if __name__ == '__main__':
    numthreads = 7
    q = Queue.Queue(maxsize=numthreads * 2)
    r = Queue.Queue()
    qts = [QueryThread(q, r) for i in range(numthreads)]
    st = ReportThread(r)
    for t in qts:
        t.start()
    st.start()

    signal.signal(signal.SIGINT, sighand)
    for domain in itertools.cycle(domains):
        if stop:
            break
        q.put(domain)
    for t in qts:
        t.join()
    st.join()
