#!/usr/bin/env python

import threading
import Queue
import time
# requires dnspython
import dns.exception
import dns.query
import dns.rdatatype

class Result(object):
    def __init__(self, query, ans, elapsed):
        self.query = query
        self.ans = ans
        self.elapsed = elapsed

def summerize(q):
    rs = []
    while not q.empty():
        rs.append(q.get())
    if len(rs) == 0:
        return
    total = len(rs)
    finished = len([r for r in rs if r.ans is not None])
    timeout = total - finished
    total_wait = sum([r.elapsed for r in rs])
    finished_wait = sum([r.elapsed for r in rs if r.ans is not None])
    timeout_wait = total_wait - finished_wait
    avg_wait = total_wait / total
    avg_finished_wait = finished_wait / finished
    summary = (
   '            total: %(total)d\n'
   '         finished: %(finished)d\n'
   '          timeout: %(timeout)d\n'
   '         avg_wait: %(avg_wait).3f\n'
   'avg_finished_wait: %(avg_finished_wait).3f\n'
    )
    summary = summary % {
        'total': total,
        'finished': finished,
        'timeout': timeout,
        'avg_wait': avg_wait,
        'avg_finished_wait': avg_finished_wait,
    }
    print summary


class QueryThread(threading.Thread):
    def __init__(self, q, r, *args, **kwargs):
        super(QueryThread, self).__init__(*args, **kwargs)
        self.q = q
        self.r = r

    def run(self):
        while True:
            try:
                domain = self.q.get(True, 2)
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

class UtdnsdThread(threading.Thread):
    pass

if __name__ == '__main__':
    q = Queue.Queue()
    r = Queue.Queue()
    ts = [QueryThread(q, r) for i in range(10)]
    for t in ts:
        t.start()
    for i in range(10):
        q.put('www.baidu.com')
        q.put('www.twitter.com')
        q.put('www.facebook.com')
        q.put('www.vimeo.com')
        q.put('mail.google.com')
        q.put('www.google.com')
        q.put('www.amazon.com')
        q.put('aws.amazon.com')
        q.put('www.openvpn.net')
    for t in ts:
        t.join()
    summerize(r)
