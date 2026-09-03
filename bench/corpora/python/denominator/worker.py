import queue


def drain(work: queue.Queue) -> int:
    return work.qsize()
